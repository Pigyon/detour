package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nedlir/detour/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalDefaults(t *testing.T) {
	t.Parallel()

	v := config.NewViper()
	cfg, err := config.Unmarshal(v)
	require.NoError(t, err)
	assert.Equal(t, config.DefaultCanary, cfg.Canary)
	assert.Equal(t, "info", cfg.LogLevel)
	assert.Equal(t, 10, cfg.Concurrency)
	assert.InDelta(t, 5.0, cfg.Rate, 0.001)
	assert.Equal(t, 10*time.Second, cfg.Timeout)
	assert.Equal(t, time.Duration(0), cfg.Budget, "no budget by default means unlimited")
	require.NotNil(t, cfg.Headers)
	assert.Empty(t, cfg.Headers)
}

func TestLoadFileOverridesDefault(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "detour.yaml")
	require.NoError(t, os.WriteFile(path, []byte("canary: file.invalid\nlog-level: debug\n"), 0o600))

	v := config.NewViper()
	require.NoError(t, config.LoadFile(v, path))

	cfg, err := config.Unmarshal(v)
	require.NoError(t, err)
	assert.Equal(t, "file.invalid", cfg.Canary)
	assert.Equal(t, "debug", cfg.LogLevel)
}

func TestEnvOverridesFile(t *testing.T) {
	v := config.NewViper()
	dir := t.TempDir()
	path := filepath.Join(dir, "detour.yaml")
	require.NoError(t, os.WriteFile(path, []byte("canary: file.invalid\n"), 0o600))
	require.NoError(t, config.LoadFile(v, path))

	t.Setenv("DETOUR_CANARY", "env.invalid")

	cfg, err := config.Unmarshal(v)
	require.NoError(t, err)
	assert.Equal(t, "env.invalid", cfg.Canary)
}

func TestExplicitSetOverridesEnv(t *testing.T) {
	t.Setenv("DETOUR_CANARY", "env.invalid")

	v := config.NewViper()
	v.Set("canary", "flag.invalid")

	cfg, err := config.Unmarshal(v)
	require.NoError(t, err)
	assert.Equal(t, "flag.invalid", cfg.Canary)
}

func TestMissingConfigFileIsOK(t *testing.T) {
	t.Parallel()

	v := config.NewViper()
	require.NoError(t, config.LoadFile(v, ""))
}

func TestParseHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     []string
		wantKey string
		wantVal string
		wantErr bool
	}{
		{
			name:    "bearer",
			raw:     []string{"Authorization: Bearer tok"},
			wantKey: "Authorization",
			wantVal: "Bearer tok",
		},
		{
			name:    "missing colon",
			raw:     []string{"Authorization Bearer tok"},
			wantErr: true,
		},
		{
			name:    "empty name",
			raw:     []string{": value"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := config.ParseHeaders(tt.raw)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantVal, got.Get(tt.wantKey))
		})
	}
}

const destHost = "evil.example"

func TestDestination(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  config.Config
		want string
	}{
		{
			name: "default is the google.com host",
			cfg:  config.Config{Canary: config.DefaultCanary, RedirectTo: config.DefaultRedirectTo},
			want: "google.com",
		},
		{
			name: "a bare host with a path keeps only the host",
			cfg:  config.Config{RedirectTo: destHost + "/path"},
			want: destHost,
		},
		{
			name: "userinfo is not the host",
			cfg:  config.Config{RedirectTo: "user:pw@" + destHost},
			want: destHost,
		},
		{
			name: "a trailing dot is dropped",
			cfg:  config.Config{RedirectTo: destHost + "."},
			want: destHost,
		},
		{
			name: "case is normalized",
			cfg:  config.Config{RedirectTo: "HTTPS://" + "EVIL.EXAMPLE" + "/"},
			want: destHost,
		},
		{
			name: "a url is reduced to its host",
			cfg:  config.Config{RedirectTo: "https://" + destHost + "/pwn?x=1"},
			want: destHost,
		},
		{
			name: "a bare host is taken as given",
			cfg:  config.Config{RedirectTo: destHost},
			want: destHost,
		},
		{
			name: "a host and port drops the port",
			cfg:  config.Config{RedirectTo: destHost + ":8443"},
			want: destHost,
		},
		{
			name: "the deprecated canary flag still wins when set",
			cfg:  config.Config{Canary: "old.invalid", RedirectTo: config.DefaultRedirectTo},
			want: "old.invalid",
		},
		{
			name: "an unset canary does not override",
			cfg:  config.Config{Canary: config.DefaultCanary, RedirectTo: "https://" + destHost + "/"},
			want: destHost,
		},
		{
			name: "everything empty falls back to a non-resolving name",
			cfg:  config.Config{},
			want: config.DefaultCanary,
		},
		{
			name: "whitespace is not a destination",
			cfg:  config.Config{RedirectTo: "   "},
			want: config.DefaultCanary,
		},
		{
			name: "a scheme with no host is not a destination",
			cfg:  config.Config{RedirectTo: "https://"},
			want: config.DefaultCanary,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, tt.cfg.Destination())
		})
	}
}

// TestUnmarshalRejectsBadDestination keeps a broken destination from starting a
// run. An empty one switches the scope guard off for every host at once, which
// is the worst possible way to fail.
func TestUnmarshalRejectsBadDestination(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"   ", "https://", "?a=b", "/just/a/path", "nodots"} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			v := config.NewViper()
			v.Set("redirect-to", raw)

			_, err := config.Unmarshal(v)
			require.Error(t, err, "a destination of %q must not start a run", raw)
		})
	}
}

func TestUnmarshalAcceptsUsableDestinations(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"https://google.com", "google.com", "evil.example:8443", "localhost"} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			v := config.NewViper()
			v.Set("redirect-to", raw)

			cfg, err := config.Unmarshal(v)
			require.NoError(t, err)
			assert.NotEmpty(t, cfg.Destination())
		})
	}
}

func TestBudgetRounds(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want []time.Duration
		err  bool
	}{
		{name: "empty yields no rounds", in: "", want: nil},
		{name: "single", in: "30m", want: []time.Duration{30 * time.Minute}},
		{name: "several", in: "30m,1h,2h", want: []time.Duration{30 * time.Minute, time.Hour, 2 * time.Hour}},
		{name: "spaces and blanks", in: " 30m , , 1h ", want: []time.Duration{30 * time.Minute, time.Hour}},
		{name: "invalid entry", in: "30m,nope", err: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := config.Config{BudgetExpand: tc.in}.BudgetRounds()
			if tc.err {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
