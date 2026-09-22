package cli_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nedlir/detour/internal/lab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// selectedEntry mirrors a corpus entry as the command prints it.
type selectedEntry struct {
	URL    string   `json:"url"`
	Kinds  []string `json:"kinds"`
	Params []string `json:"params"`
	Vendor string   `json:"vendor"`
}

func TestSelectCommandRanksAndDedupes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	list := filepath.Join(dir, "urls.txt")
	require.NoError(t, os.WriteFile(list, []byte(strings.Join([]string{
		"https://a.lab/article/1?next=/home",
		"https://a.lab/article/2?next=/home",
		"https://a.lab/article/3?next=/home",
		"https://a.lab/article/4?next=/home",
		"https://mail.a.lab/ls/click?upn=eyJ1cmwiOiJodHRwczovL2EuYi8ifQ",
		"https://a.lab/style.css",
		"https://a.lab/about",
	}, "\n")+"\n"), 0o600))

	out, errOut := runCLI(t, selectArgs(list))

	entries := decodeSelected(t, out)
	require.NotEmpty(t, entries)

	assert.Equal(t, "vendor-sig", firstKind(entries[0]), "the click wrapper ranks first")
	assert.Equal(t, "sendgrid", entries[0].Vendor)
	assert.Len(t, entries, 3, "four identical shapes collapse to two, plus the wrapper")
	assert.Contains(t, errOut, "of 7 urls selected")
}

func TestSelectCommandVendorOnly(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	list := filepath.Join(dir, "urls.txt")
	require.NoError(t, os.WriteFile(list, []byte(strings.Join([]string{
		"https://a.lab/go?next=/home",
		"https://mail.a.lab/ls/click?upn=eyJ1cmwiOiJodHRwczovL2EuYi8ifQ",
	}, "\n")+"\n"), 0o600))

	out, _ := runCLI(t, selectArgs(list, "--vendor-only"))

	entries := decodeSelected(t, out)
	require.Len(t, entries, 1)
	assert.Equal(t, "sendgrid", entries[0].Vendor)
}

func TestSelectCommandReadsStdin(t *testing.T) {
	t.Parallel()

	cmd := newRootWith(t, selectArgs("-"))
	out := new(strings.Builder)

	cmd.SetOut(out)
	cmd.SetIn(strings.NewReader("https://a.lab/go?url=https://b.lab/\n"))

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "https://a.lab/go")
}

func TestDorksCommand(t *testing.T) {
	t.Parallel()

	out, errOut := runCLI(t, dorksArgs("example.com"))

	var queries []struct {
		Engine string `json:"engine"`
		Query  string `json:"query"`
		Why    string `json:"why"`
	}

	require.NoError(t, json.Unmarshal([]byte(out), &queries))
	require.NotEmpty(t, queries)
	assert.Contains(t, errOut, "queries")

	var joined strings.Builder

	for _, q := range queries {
		joined.WriteString(q.Query)
		joined.WriteString("\n")
	}

	assert.Contains(t, joined.String(), "site:example.com")
}

func TestDorksCommandRaw(t *testing.T) {
	t.Parallel()

	out, _ := runCLI(t, dorksArgs("example.com", "--raw"))

	lines := strings.Split(strings.TrimSpace(out), "\n")
	assert.NotEmpty(t, lines)

	for _, line := range lines {
		assert.NotContains(t, line, "{", "raw output is bare queries")
	}
}

// TestHarvestPassiveIssuesZeroTargetRequests is the command-level contract of
// --passive.
func TestHarvestPassiveIssuesZeroTargetRequests(t *testing.T) {
	t.Parallel()

	var hits atomic.Int64

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)

	// The archives are unreachable under the scope guard, which is fine: the
	// assertion is about the target, not about finding anything.
	cmd := newRootWith(t, harvestArgs(target.URL, "--passive", "--scope-file", scopeFile(t, "127.0.0.1")))
	_ = cmd.Execute()

	assert.Zero(t, hits.Load(), "passive must never touch the target")
}

// TestPipelineEndToEnd runs the whole thing against the lab: harvest the
// target, select injection points, attack them.
func TestPipelineEndToEnd(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	dir := t.TempDir()

	out, errOut := runCLI(t, []string{
		flagRate, "200",
		"--scope-file", scopeFile(t, "127.0.0.1"),
		"--crawl=false",
		"--out", dir,
		srv.URL + "/a01?url=https://allowed.lab/",
	})

	assert.Contains(t, errOut, "selected")
	assert.Contains(t, out, `"technique_id"`, "the pipeline reaches the attack stage")

	for _, name := range []string{"harvested.json", "selected.json", "findings.jsonl"} {
		_, err := os.Stat(filepath.Join(dir, name))
		assert.NoError(t, err, "%s written", name)
	}
}

// scopeFile writes a scope list so a test run cannot leave the loopback.
func scopeFile(t *testing.T, hosts ...string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "scope.txt")
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(hosts, "\n")+"\n"), 0o600))

	return path
}

func decodeSelected(t *testing.T, out string) []selectedEntry {
	t.Helper()

	entries := []selectedEntry{}

	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var entry selectedEntry

		require.NoError(t, json.Unmarshal([]byte(line), &entry))

		entries = append(entries, entry)
	}

	return entries
}

func firstKind(entry selectedEntry) string {
	if len(entry.Kinds) == 0 {
		return ""
	}

	for _, kind := range entry.Kinds {
		if kind == "vendor-sig" {
			return kind
		}
	}

	return entry.Kinds[0]
}

func selectArgs(extra ...string) []string {
	return append([]string{flagRate, "50", "select"}, extra...)
}

func dorksArgs(extra ...string) []string {
	return append([]string{flagRate, "50", "dorks"}, extra...)
}

func harvestArgs(extra ...string) []string {
	return append([]string{flagRate, "50", "harvest"}, extra...)
}
