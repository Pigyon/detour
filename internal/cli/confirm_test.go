package cli_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nedlir/detour/internal/cli"
	"github.com/nedlir/detour/internal/confirm"
	"github.com/nedlir/detour/internal/lab"
	"github.com/nedlir/detour/internal/model"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func requireChrome(t *testing.T) {
	t.Helper()

	if !confirm.Available() {
		t.Skip("no chrome or chromium installed; headless confirmation is opt-in")
	}
}

// writeCandidate lays down a findings list the way a previous run would.
func writeCandidate(t *testing.T, dir, source, param string) string {
	t.Helper()

	f := model.NewFinding()
	f.TechniqueID = "OR-C01"
	f.Mechanism = "js"
	f.Payload = "https://{{canary}}/x"
	f.Verdict = model.VerdictCandidate
	f.Candidate = model.NewNavigationCandidate(source, model.RepresentationJSExpression)
	f.Candidate.ParamName = param

	raw, err := json.Marshal(f)
	require.NoError(t, err)

	path := filepath.Join(dir, "hits.jsonl")
	require.NoError(t, os.WriteFile(path, append(raw, '\n'), 0o600))

	return path
}

func TestConfirmCommandPromotesFromList(t *testing.T) {
	t.Parallel()
	requireChrome(t)

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	list := writeCandidate(t, dir, srv.URL+"/c01", "backUrl")

	out, errOut := runCLI(t, confirmArgs("-l", list))

	var f map[string]any

	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(out)), &f))
	assert.Equal(t, "confirmed", f["verdict"])
	assert.Contains(t, errOut, "1 confirmed")

	caps, ok := f["capabilities"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, caps["browser_confirmed"])
}

func TestConfirmCommandWritesReport(t *testing.T) {
	t.Parallel()
	requireChrome(t)

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	list := writeCandidate(t, dir, srv.URL+"/c01", "backUrl")
	outDir := filepath.Join(dir, "run")

	runCLI(t, confirmArgs("-l", list, "--out", outDir))

	for _, name := range []string{"findings.jsonl", "findings.json", "REPORT.md"} {
		_, err := os.Stat(filepath.Join(outDir, name))
		assert.NoError(t, err, "%s written", name)
	}
}

func TestConfirmCommandRefererTest(t *testing.T) {
	t.Parallel()
	requireChrome(t)

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	out, _ := runCLI(t, confirmArgs("--referer-test", srv.URL+"/d05"))

	var result map[string]any

	require.NoError(t, json.Unmarshal([]byte(out), &result))
	assert.Equal(t, true, result["returned"])
	assert.Equal(t, true, result["confirmed"])
}

func TestConfirmCommandNeedsAList(t *testing.T) {
	t.Parallel()
	requireChrome(t)

	cmd := newRootWith(t, confirmArgs())

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "findings.jsonl")
}

// TestAttackHeadlessDegradesWithoutChrome is the graceful path: a scan still
// produces its findings when no browser is installed.
func TestAttackHeadlessDegradesWithoutChrome(t *testing.T) {
	t.Setenv("DETOUR_CHROME", "/nonexistent/chrome")

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	list := filepath.Join(dir, "urls.txt")
	require.NoError(t, os.WriteFile(list, []byte(srv.URL+"/a01?url=https://allowed.lab/\n"), 0o600))

	cmd := newRootWith(t, append(attackArgs(list), "--headless"))
	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)

	cmd.SetOut(out)
	cmd.SetErr(errOut)

	require.NoError(t, cmd.Execute(), "a missing browser must not fail the run")
	assert.Contains(t, out.String(), `"technique_id"`, "findings survive")
}

// flagRate keeps the CLI tests from throttling against the in-process lab.
const flagRate = "--rate"

func confirmArgs(extra ...string) []string {
	return append([]string{flagRate, "50", "confirm"}, extra...)
}

// newRootWith builds a command tree with args set, for cases that assert on
// the error rather than the output.
func newRootWith(t *testing.T, args []string) *cobra.Command {
	t.Helper()

	cmd := cli.NewRoot()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs(args)

	return cmd
}

// runCLI executes a command tree and returns its streams.
func runCLI(t *testing.T, args []string) (string, string) {
	t.Helper()

	cmd := cli.NewRoot()
	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)

	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs(args)

	require.NoError(t, cmd.Execute())

	return out.String(), errOut.String()
}
