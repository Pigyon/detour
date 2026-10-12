package cli_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nedlir/detour/internal/cli"
	"github.com/nedlir/detour/internal/lab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttackCommandJSONL(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	list := filepath.Join(t.TempDir(), "urls.txt")
	require.NoError(t, os.WriteFile(list, []byte(srv.URL+"/a01?url=https://allowed.lab/\n"), 0o600))

	cmd := cli.NewRoot()
	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)

	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs(attackArgs(list))

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), `"technique_id"`)
	assert.Contains(t, errOut.String(), "findings")
	assert.Contains(t, out.String(), `"severity"`, "every finding must carry a suggested severity")
}

func TestAttackCommandHAR(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	har := `{"log":{"entries":[{"request":{"url":"` + srv.URL + `/a01?url=https://allowed.lab/"}}]}}`
	path := filepath.Join(t.TempDir(), "run.har")
	require.NoError(t, os.WriteFile(path, []byte(har), 0o600))

	cmd := cli.NewRoot()
	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)

	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs(attackArgs(path))

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), `"technique_id"`)
	assert.Contains(t, errOut.String(), "findings")
}

func TestAttackCommandFilterAndOut(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	list := filepath.Join(t.TempDir(), "urls.txt")
	body := srv.URL + "/a01?url=https://allowed.lab/\n" + srv.URL + "/d01\n"
	require.NoError(t, os.WriteFile(list, []byte(body), 0o600))

	outDir := filepath.Join(t.TempDir(), "out")
	cmd := cli.NewRoot()
	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)

	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs(attackArgs("--filter", "header", flagOut, outDir, list))

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), `"OR-D01"`)
	assert.NotContains(t, out.String(), `"OR-A01"`)

	md, err := os.ReadFile(filepath.Join(outDir, "REPORT.md")) //nolint:gosec // G304: outDir is t.TempDir output we wrote.
	require.NoError(t, err)
	assert.Contains(t, string(md), "OR-D01")
	assert.NotContains(t, string(md), "OR-A01")
}

func TestAttackCommandResume(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	list := filepath.Join(t.TempDir(), "urls.txt")
	require.NoError(t, os.WriteFile(list, []byte(srv.URL+"/a01?url=https://allowed.lab/\n"), 0o600))

	ckpt := filepath.Join(t.TempDir(), "run.ckpt")

	run := func() string {
		cmd := cli.NewRoot()
		out := new(bytes.Buffer)
		errOut := new(bytes.Buffer)

		cmd.SetOut(out)
		cmd.SetErr(errOut)
		cmd.SetArgs(attackArgs("--resume", ckpt, list))
		require.NoError(t, cmd.Execute())

		return errOut.String()
	}

	// A resumed run repeats no work and loses no findings, so it reports the
	// same count. Reporting zero is how an interrupted scan used to come back
	// empty and overwrite the report that had the answers.
	first := run()
	assert.NotEqual(t, "0 findings\n", first)
	assert.Equal(t, first, run())
}

// TestAttackCommandReportsDiffOnRerun proves a second run into the same
// --out says what changed, and a first run says nothing (there is nothing
// to diff against yet).
// TestAttackCommandWritesOpaqueEnvelopeBreakdown is end to end: a target
// that never acts on a decodable envelope still gets the full decoded
// breakdown written to --out, not just a debug log line saying one exists.
func TestAttackCommandWritesOpaqueEnvelopeBreakdown(t *testing.T) {
	t.Parallel()

	unresponsive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(unresponsive.Close)

	blob, err := lab.EncodeClick("https://" + lab.AllowedHost + "/home")
	require.NoError(t, err)

	target := unresponsive.URL + "/track/click2/" + blob + ".html"

	list := filepath.Join(t.TempDir(), "urls.txt")
	require.NoError(t, os.WriteFile(list, []byte(target+"\n"), 0o600))

	dir := t.TempDir()

	cmd := cli.NewRoot()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs(attackArgs(flagOut, dir, list))

	require.NoError(t, cmd.Execute())

	raw, err := os.ReadFile(filepath.Join(dir, "opaque_envelopes.json")) //nolint:gosec // G304: dir is t.TempDir output.
	require.NoError(t, err)
	assert.Contains(t, string(raw), target)
}

func TestAttackCommandReportsDiffOnRerun(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	list := filepath.Join(t.TempDir(), "urls.txt")
	require.NoError(t, os.WriteFile(list, []byte(srv.URL+"/a01?url=https://allowed.lab/\n"), 0o600))

	dir := t.TempDir()

	run := func() string {
		cmd := cli.NewRoot()
		out := new(bytes.Buffer)
		errOut := new(bytes.Buffer)

		cmd.SetOut(out)
		cmd.SetErr(errOut)
		cmd.SetArgs(attackArgs(flagOut, dir, list))
		require.NoError(t, cmd.Execute())

		return errOut.String()
	}

	first := run()
	assert.NotContains(t, first, "since the last run",
		"a first run has nothing to diff against yet")

	second := run()
	assert.Contains(t, second, "since the last run into this directory")
}

// TestAttackCommandRespectsBudget proves --budget stops a run before it
// would otherwise finish, and still exits clean rather than erroring.
func TestAttackCommandRespectsBudget(t *testing.T) {
	t.Parallel()

	const perRequestDelay = 150 * time.Millisecond

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(perRequestDelay)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	urls := make([]string, 20)
	for i := range urls {
		urls[i] = fmt.Sprintf("%s/?url=https://allowed.lab/%d", srv.URL, i)
	}

	list := filepath.Join(t.TempDir(), "urls.txt")
	require.NoError(t, os.WriteFile(list, []byte(strings.Join(urls, "\n")+"\n"), 0o600))

	start := time.Now()

	cmd := cli.NewRoot()
	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)

	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs(append([]string{"--budget", "300ms"}, attackArgs(list)...))

	require.NoError(t, cmd.Execute(), "a budget running out must not be reported as a failure")

	elapsed := time.Since(start)
	allRequestsWouldHaveTaken := perRequestDelay * time.Duration(len(urls))

	assert.Less(t, elapsed, allRequestsWouldHaveTaken,
		"the budget must cut the run short rather than letting every request run")
	assert.Contains(t, errOut.String(), "stopped early",
		"a run cut short by its budget must say so, the same as Ctrl-C")
}

func attackArgs(extra ...string) []string {
	return append([]string{flagRate, "50", "attack"}, extra...)
}

// TestAttackCommandBudgetExpandResumesAndFinishes proves --budget-expand runs
// under the first budget, is cut, then resumes under the next and finishes,
// keeping the findings the first round proved rather than losing them.
func TestAttackCommandBudgetExpandResumesAndFinishes(t *testing.T) {
	t.Parallel()

	const perRequest = 120 * time.Millisecond

	labHandler := lab.New().Handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(perRequest)
		labHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	urls := make([]string, 5)
	for i := range urls {
		urls[i] = fmt.Sprintf("%s/a01?url=https://allowed.lab/%d", srv.URL, i)
	}

	list := filepath.Join(t.TempDir(), "urls.txt")
	require.NoError(t, os.WriteFile(list, []byte(strings.Join(urls, "\n")+"\n"), 0o600))

	outDir := t.TempDir()

	cmd := cli.NewRoot()
	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)

	cmd.SetOut(out)
	cmd.SetErr(errOut)
	// Concurrency 1 serializes the requests so the tiny first round cannot
	// finish and must be resumed under the generous second one.
	cmd.SetArgs([]string{
		flagRate, "50", "--concurrency", "1", "--budget-expand", "200ms,30s",
		flagOut, outDir, "attack", list,
	})

	require.NoError(t, cmd.Execute(), "a resumed budget run must exit clean")
	assert.Contains(t, errOut.String(), "resuming with more time",
		"the first budget round must be cut and resumed")
	assert.Contains(t, out.String(), `"technique_id"`,
		"findings proved before the resume must survive into the final report")
}
