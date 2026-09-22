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
	"github.com/nedlir/detour/internal/lab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jsOutput mirrors the command's JSON so the test reads it as data.
type jsOutput struct {
	URL     string `json:"url"`
	Scripts []struct {
		Source string `json:"source"`
		Sinks  []struct {
			Kind      string   `json:"kind"`
			Guards    []string `json:"guards"`
			Validator *struct {
				Name      string   `json:"name"`
				Kind      string   `json:"kind"`
				Allowlist []string `json:"allowlist"`
			} `json:"validator"`
		} `json:"sinks"`
	} `json:"scripts"`
	Verdicts []struct {
		TechniqueID string `json:"technique_id"`
		Severity    string `json:"severity"`
		Discrepancy string `json:"discrepancy"`
	} `json:"verdicts"`
	Errors []string `json:"errors"`
}

func TestJSCommandAgainstLab(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	out, errOut := runJSCmd(t, jsArgs(srv.URL+"/app/signin"))

	var report jsOutput

	require.NoError(t, json.Unmarshal([]byte(out), &report))
	assert.Empty(t, report.Errors)
	require.Len(t, report.Scripts, 1)
	require.Len(t, report.Scripts[0].Sinks, 1)

	sink := report.Scripts[0].Sinks[0]
	assert.Equal(t, "location.href", sink.Kind)
	require.NotNil(t, sink.Validator)
	assert.Equal(t, "isTrusted", sink.Validator.Name)
	assert.Equal(t, "suffix", sink.Validator.Kind)
	assert.Equal(t, []string{"allowed.lab", "cdn.allowed.lab"}, sink.Validator.Allowlist)

	assert.Contains(t, techniques(report), "OR-A13")
	assert.Contains(t, errOut, "verdicts")
}

func TestJSCommandDecoyStaysSilent(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	out, _ := runJSCmd(t, jsArgs(srv.URL+"/decoy/guarded"))

	var report jsOutput

	require.NoError(t, json.Unmarshal([]byte(out), &report))
	require.Len(t, report.Scripts, 1, "the bundle is read")
	assert.NotEmpty(t, report.Scripts[0].Sinks, "its sink is found")
	assert.Empty(t, report.Verdicts, "but a correct guard yields nothing")
}

func TestJSCommandLocalFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "bundle.js")
	require.NoError(t, os.WriteFile(path, []byte(`function g(u){ location.href = u }`), 0o600))

	out, _ := runJSCmd(t, jsArgs(path))

	var report jsOutput

	require.NoError(t, json.Unmarshal([]byte(out), &report))
	assert.Contains(t, techniques(report), "OR-C01")
}

func TestJSCommandFindingsAreCandidates(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "bundle.js")
	require.NoError(t, os.WriteFile(path, []byte(`function g(u){ location.href = u }`), 0o600))

	out, _ := runJSCmd(t, jsArgs(path, "--findings"))
	require.NotEmpty(t, strings.TrimSpace(out))

	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		var finding map[string]any

		require.NoError(t, json.Unmarshal([]byte(line), &finding))
		assert.Equal(t, "candidate", finding["verdict"])
		assert.Equal(t, "js", finding["mechanism"])
		assert.Equal(t, "1", finding["schema_version"])
	}
}

func TestJSCommandWritesReport(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.js")
	require.NoError(t, os.WriteFile(path, []byte(`function g(u){ location.href = u }`), 0o600))

	outDir := filepath.Join(dir, "run")
	runJSCmd(t, jsArgs(path, "--out", outDir))

	for _, name := range []string{"findings.jsonl", "findings.json", "report.md"} {
		_, err := os.Stat(filepath.Join(outDir, name))
		assert.NoError(t, err, "%s written", name)
	}
}

func runJSCmd(t *testing.T, args []string) (string, string) {
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

func techniques(report jsOutput) []string {
	out := make([]string, 0, len(report.Verdicts))
	for _, v := range report.Verdicts {
		out = append(out, v.TechniqueID)
	}

	return out
}

func jsArgs(extra ...string) []string {
	return append([]string{flagRate, "50", "js"}, extra...)
}
