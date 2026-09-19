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
