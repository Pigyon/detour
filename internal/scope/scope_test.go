package scope_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nedlir/detour/internal/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGuardCheck(t *testing.T) {
	t.Parallel()

	g, err := scope.Parse([]string{
		"example.com",
		"*.example.com",
		"!evil.example.com",
		"https://shop.target.com/app",
	}, "canary.invalid")
	require.NoError(t, err)

	tests := []struct {
		name    string
		host    string
		wantErr error
	}{
		{name: "exact apex", host: "example.com"},
		{name: "wildcard subdomain", host: "app.example.com"},
		{name: "nested wildcard", host: "a.b.example.com"},
		{name: "url host in list", host: "shop.target.com"},
		{name: "denied override", host: "evil.example.com", wantErr: scope.ErrOutOfScope},
		{name: "unlisted", host: "other.com", wantErr: scope.ErrOutOfScope},
		{name: "canary", host: "canary.invalid", wantErr: scope.ErrCanary},
		{name: "canary with port", host: "canary.invalid:443", wantErr: scope.ErrCanary},
		{name: "wildcard does not match sibling", host: "example.org", wantErr: scope.ErrOutOfScope},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := g.Check(tt.host)
			if tt.wantErr == nil {
				require.NoError(t, err)
				assert.True(t, g.Allows(tt.host))

				return
			}

			require.ErrorIs(t, err, tt.wantErr)
			assert.False(t, g.Allows(tt.host))
		})
	}
}

func TestEmptyScopeAllowsAllButCanary(t *testing.T) {
	t.Parallel()

	g := scope.New("canary.invalid")
	require.NoError(t, g.Check("anywhere.example"))
	require.ErrorIs(t, g.Check("canary.invalid"), scope.ErrCanary)
}

func TestCheckURL(t *testing.T) {
	t.Parallel()

	g, err := scope.Parse([]string{"example.com"}, "canary.invalid")
	require.NoError(t, err)
	require.NoError(t, g.CheckURL("https://example.com/go?next=1"))
	require.ErrorIs(t, g.CheckURL("https://evil.com/"), scope.ErrOutOfScope)
	require.ErrorIs(t, g.CheckURL("https://canary.invalid/landed"), scope.ErrCanary)
}

func TestHostOfBareHost(t *testing.T) {
	t.Parallel()

	host, err := scope.HostOf("example.com")
	require.NoError(t, err)
	assert.Equal(t, "example.com", host)
}

func TestLoadFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "scope.txt")
	require.NoError(t, os.WriteFile(path, []byte("example.com\n*.example.com\n"), 0o600))

	g, err := scope.LoadFile(path, "canary.invalid")
	require.NoError(t, err)
	require.NoError(t, g.Check("www.example.com"))
}
