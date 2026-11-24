package cli_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nedlir/detour/internal/cli"
	"github.com/nedlir/detour/internal/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runAttack runs the attack command over urls and returns stderr and the
// output directory.
func runAttack(t *testing.T, urls string, extra ...string) (string, string) {
	t.Helper()

	list := filepath.Join(t.TempDir(), "urls.txt")
	require.NoError(t, os.WriteFile(list, []byte(urls), 0o600))

	dir := t.TempDir()
	errOut := new(bytes.Buffer)

	cmd := cli.NewRoot()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(errOut)
	cmd.SetArgs(attackArgs(append(append([]string{}, extra...), flagOut, dir, list)...))

	require.NoError(t, cmd.Execute())

	return errOut.String(), dir
}

func readUntested(t *testing.T, dir string) report.Untested {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(dir, "untested.json")) //nolint:gosec // G304: dir is t.TempDir output.
	require.NoError(t, err)

	var u report.Untested
	require.NoError(t, json.Unmarshal(raw, &u))

	return u
}

// TestAttackCommandReportsBlockedProbesAsUntested is the operator's view of a
// WAF: the summary says the probes were refused and by whom, and --out keeps
// the list, instead of a bare "0 findings".
func TestAttackCommandReportsBlockedProbesAsUntested(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/go" && r.URL.Query().Get("url") == "https://allowed.lab/" &&
			r.Header.Get("X-Forwarded-Host") == "" {
			w.WriteHeader(http.StatusOK)

			return
		}

		w.Header().Set("Cf-Mitigated", "challenge")
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	stderr, dir := runAttack(t, srv.URL+"/go?url=https://allowed.lab/\n")

	assert.Contains(t, stderr, "untested:")
	assert.Contains(t, stderr, "cloudflare")

	u := readUntested(t, dir)
	assert.Positive(t, u.Blocked)
	assert.Equal(t, u.Blocked, u.BlockedBy["cloudflare"])
	assert.NotEmpty(t, u.BlockedProbes)
	assert.Empty(t, u.AuthWalls)
}

// TestAttackCommandReportsAuthWalls lists walled sources and says how to test
// them, and --attack-auth-walls sends the payloads anyway.
func TestAttackCommandReportsAuthWalls(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/users/sign_in", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	source := srv.URL + "/account?next=https://allowed.lab/"

	stderr, dir := runAttack(t, source+"\n")
	assert.Contains(t, stderr, "needs auth: 1 urls")

	u := readUntested(t, dir)
	require.Len(t, u.AuthWalls, 1)
	assert.Equal(t, source, u.AuthWalls[0].URL)
	assert.Equal(t, "/users/sign_in", u.AuthWalls[0].Location)

	stderr, dir = runAttack(t, source+"\n", "--attack-auth-walls")
	assert.NotContains(t, stderr, "needs auth")

	_, err := os.Stat(filepath.Join(dir, "untested.json"))
	assert.True(t, os.IsNotExist(err))
}
