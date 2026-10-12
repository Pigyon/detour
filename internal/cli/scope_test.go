package cli_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nedlir/detour/internal/cli"
	"github.com/nedlir/detour/internal/hackerone"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScopeTestCommand(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "scope.txt")
	require.NoError(t, os.WriteFile(path, []byte("app.test\n"), 0o600))

	tests := []struct {
		name      string
		url       string
		want      string
		wantError bool
	}{
		{name: "in scope", url: "https://app.test/x", want: "IN-SCOPE"},
		{name: "out of scope", url: "https://evil.com/", want: "OUT-OF-SCOPE", wantError: true},
		// Neither destination is ever contacted: the primary one payloads aim
		// at, nor the second one the input_controlled check uses.
		{name: "default destination", url: "https://google.com/", want: "CANARY", wantError: true},
		{name: "second destination", url: "https://example.com/", want: "CANARY", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd := cli.NewRoot()
			out := new(bytes.Buffer)
			cmd.SetOut(out)
			cmd.SetErr(new(bytes.Buffer))
			cmd.SetArgs([]string{flagScopeFile, path, cmdScope, "test", tt.url})

			err := cmd.Execute()

			assert.Contains(t, out.String(), tt.want)

			if tt.wantError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

const importFixture = `{
	"relationships": {
		"structured_scopes": {
			"data": [
				{"attributes": {"asset_identifier": "acme.com", "asset_type": "URL",
					"eligible_for_submission": true, "eligible_for_bounty": true}},
				{"attributes": {"asset_identifier": "*.acme.com", "asset_type": "WILDCARD",
					"eligible_for_submission": true, "eligible_for_bounty": true}}
			]
		}
	}
}`

// TestScopeImportWritesAScopeFile is end to end against a local stand-in for
// the hacker API, proving the output is in the exact format --scope-file
// already reads.
func TestScopeImportWritesAScopeFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/acme", r.URL.Path)

		_, _ = w.Write([]byte(importFixture))
	}))
	t.Cleanup(srv.Close)

	previous := hackerone.APIBase
	hackerone.APIBase = srv.URL

	t.Cleanup(func() { hackerone.APIBase = previous })

	t.Setenv("DETOUR_HACKERONE_TOKEN", "test-token")

	scopePath := filepath.Join(t.TempDir(), "scope.txt")

	cmd := cli.NewRoot()
	cmd.SetOut(new(bytes.Buffer))
	errOut := new(bytes.Buffer)
	cmd.SetErr(errOut)
	cmd.SetArgs([]string{cmdScope, "import", "--hackerone", "acme", "--username", "nedlir", flagOut, scopePath})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, errOut.String(), "2 assets written")

	written, err := os.ReadFile(scopePath) //nolint:gosec // G304: scopePath is this test's own t.TempDir output.
	require.NoError(t, err)
	assert.Equal(t, "acme.com\n*.acme.com\n", string(written))

	// The file this command just wrote has to actually work as a
	// --scope-file, not merely look like one.
	cmd2 := cli.NewRoot()
	out2 := new(bytes.Buffer)
	cmd2.SetOut(out2)
	cmd2.SetErr(new(bytes.Buffer))
	cmd2.SetArgs([]string{flagScopeFile, scopePath, cmdScope, "test", "https://sub.acme.com/x"})
	require.NoError(t, cmd2.Execute())
	assert.Contains(t, out2.String(), "IN-SCOPE")
}

// TestScopeImportRequiresTheTokenEnvVar proves the token can never be passed
// as a flag: there is no flag for it, only the env var.
func TestScopeImportRequiresTheTokenEnvVar(t *testing.T) {
	t.Setenv("DETOUR_HACKERONE_TOKEN", "")

	cmd := cli.NewRoot()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{cmdScope, "import", "--hackerone", "acme", "--username", "nedlir"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DETOUR_HACKERONE_TOKEN")
}

func TestScopeImportUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	previous := hackerone.APIBase
	hackerone.APIBase = srv.URL

	t.Cleanup(func() { hackerone.APIBase = previous })

	t.Setenv("DETOUR_HACKERONE_TOKEN", "wrong-token")

	cmd := cli.NewRoot()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{cmdScope, "import", "--hackerone", "acme", "--username", "nedlir"})

	err := cmd.Execute()
	require.ErrorIs(t, err, hackerone.ErrUnauthorized)
}
