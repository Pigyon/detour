package attack_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nedlir/detour/internal/attack"
	"github.com/nedlir/detour/internal/checkpoint"
	"github.com/nedlir/detour/internal/client"
	"github.com/nedlir/detour/internal/config"
	"github.com/nedlir/detour/internal/lab"
	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/resolve"
	"github.com/nedlir/detour/internal/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCanary is the destination the attack tests prove findings against.
const testCanary = "canary.invalid"

func newEngine(t *testing.T) (*attack.Engine, *httptest.Server) {
	t.Helper()

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	cfg := config.Config{
		Canary:      testCanary,
		Rate:        100,
		Concurrency: 4,
		Timeout:     3 * time.Second,
	}
	guard := scope.New(cfg.Canary)
	c, err := client.New(cfg, guard)
	require.NoError(t, err)

	return attack.New(c, cfg.Canary, "", cfg.Concurrency, nil), srv
}

func TestAttackFindsA01(t *testing.T) {
	t.Parallel()

	eng, srv := newEngine(t)
	findings, err := eng.Run(
		context.Background(),
		[]string{srv.URL + "/a01?url=https://allowed.lab/"},
	)
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	ids := map[string]struct{}{}
	for _, f := range findings {
		ids[f.TechniqueID] = struct{}{}
		assert.True(t, f.Capabilities.InputControlled)
		assert.True(t, f.Capabilities.RedirectExternal)
		assert.Equal(t, "1", f.SchemaVersion)

		if f.TechniqueID == "OR-A01" {
			assert.Equal(t, model.VerdictConfirmed, f.Verdict)
		}
	}

	assert.Contains(t, ids, "OR-A01")
}

func TestAttackA03IsCandidate(t *testing.T) {
	t.Parallel()

	eng, srv := newEngine(t)
	findings, err := eng.Run(
		context.Background(),
		[]string{srv.URL + "/a03?url=https://allowed.lab/"},
	)
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	found := false

	for _, f := range findings {
		if f.TechniqueID != "OR-A03" {
			continue
		}

		found = true

		assert.Equal(t, model.VerdictCandidate, f.Verdict)
		assert.False(t, f.Capabilities.BrowserConfirmed)
		assert.True(t, f.Capabilities.InputControlled)
	}

	assert.True(t, found)
}

func TestAttackKeyword(t *testing.T) {
	t.Parallel()

	eng, srv := newEngine(t)
	findings, err := eng.Run(
		context.Background(),
		[]string{srv.URL + "/a07?url=FUZZ"},
	)
	require.NoError(t, err)
	require.NotEmpty(t, findings)
}

func TestAttackHeaderD01(t *testing.T) {
	t.Parallel()

	eng, srv := newEngine(t)
	findings, err := eng.Run(context.Background(), []string{srv.URL + "/d01"})
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	found := false

	for _, f := range findings {
		if f.TechniqueID == "OR-D01" {
			found = true
		}
	}

	assert.True(t, found)
}

func TestAttackCRLFA11(t *testing.T) {
	t.Parallel()

	eng, srv := newEngine(t)
	findings, err := eng.Run(context.Background(), []string{srv.URL + "/a11/safe"})
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	found := false

	for _, f := range findings {
		if f.TechniqueID == "OR-A11" {
			found = true

			assert.Equal(t, "path_segment", f.Candidate.Representation.String())
		}
	}

	assert.True(t, found)
}

func TestAttackDecoyAllowlistZeroFP(t *testing.T) {
	t.Parallel()

	eng, srv := newEngine(t)
	findings, err := eng.Run(
		context.Background(),
		[]string{srv.URL + "/decoy/allowlist?backUrl=https://allowed.lab/home"},
	)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// TestAttackResumeReturnsCompletedFindings is what --resume exists for.
//
// The checkpoint records the attempts already made so they are not repeated,
// and the findings they produced so they are not lost. Skipping the work and
// the result both is how an interrupted scan came back reporting zero and
// overwrote the report that had the answers.
func TestAttackResumeReturnsCompletedFindings(t *testing.T) {
	t.Parallel()

	eng, srv := newEngine(t)
	path := filepath.Join(t.TempDir(), "run.ckpt")
	store, err := checkpoint.Open(path)
	require.NoError(t, err)

	eng.SetCheckpoint(store)

	urls := []string{srv.URL + "/a01?url=https://allowed.lab/"}
	first, err := eng.Run(context.Background(), urls)
	require.NoError(t, err)
	require.NotEmpty(t, first)
	require.NoError(t, store.Close())

	// A second run against the same checkpoint sends nothing and still
	// reports everything the first run proved.
	srv.Close()

	again, err := checkpoint.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = again.Close() })
	eng.SetCheckpoint(again)

	second, err := eng.Run(context.Background(), urls)
	require.NoError(t, err)

	assert.Len(t, second, len(first), "a resumed run must not lose findings")
	assert.Equal(t, techniqueSet(first), techniqueSet(second))
}

// TestUnansweredProbesAreNotRecordedAsMisses is the other half of --resume.
//
// A probe that never got an answer is not evidence of anything. Writing it to
// the checkpoint as a miss made it permanent: the attempt was skipped on
// every later run, so an interrupted scan came back short and stayed short.
// Nothing at all should be written for a host that does not answer.
func TestUnansweredProbesAreNotRecordedAsMisses(t *testing.T) {
	t.Parallel()

	// A server that is already closed answers nothing, which is what a
	// cancelled or dropped probe looks like to the engine.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := dead.URL + "/a01?url=https://allowed.lab/"
	dead.Close()

	eng, _ := newEngine(t)
	path := filepath.Join(t.TempDir(), "dead.ckpt")
	store, err := checkpoint.Open(path)
	require.NoError(t, err)

	eng.SetCheckpoint(store)

	findings, err := eng.Run(context.Background(), []string{url})
	require.NoError(t, err)
	assert.Empty(t, findings)
	require.NoError(t, store.Close())

	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is this test's own temp file.
	require.NoError(t, err)
	assert.Empty(t, strings.TrimSpace(string(raw)),
		"a host that never answered must leave no verdict behind")
}

// TestStoppedRunKeepsWhatItProved is what Ctrl-C costs.
//
// Cancellation was treated as failure at three levels, so an interrupted scan
// returned no findings, wrote no report, and exited non-zero. Stopping a long
// run cost the whole run unless --resume happened to be set.
func TestStoppedRunKeepsWhatItProved(t *testing.T) {
	t.Parallel()

	eng, srv := newEngine(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Long enough to prove something, short enough to stop mid-run.
	go func() {
		time.Sleep(700 * time.Millisecond)
		cancel()
	}()

	findings, err := eng.Run(ctx, []string{
		srv.URL + "/a01?url=https://allowed.lab/",
		srv.URL + "/a07?url=https://allowed.lab/",
		srv.URL + "/d06?url=https://allowed.lab/",
	})

	require.ErrorIs(t, err, context.Canceled, "a stopped run says it was stopped")
	assert.NotEmpty(t, findings, "and still hands back what it proved")
}

func techniqueSet(findings []model.Finding) map[string]struct{} {
	out := map[string]struct{}{}
	for _, f := range findings {
		out[f.TechniqueID] = struct{}{}
	}

	return out
}

func TestAltCanary(t *testing.T) {
	t.Parallel()

	// The second destination must never be a suffix match of the first, or the
	// input_controlled check agrees with itself for free.
	for _, primary := range []string{"canary.invalid", "google.com", "example.com", "sub.example.net"} {
		alt := attack.AltCanary(primary)
		assert.NotEqual(t, primary, alt)
		assert.False(t, resolve.HostSuffix(alt, primary), "%s must not sit under %s", alt, primary)
		assert.False(t, resolve.HostSuffix(primary, alt), "%s must not sit under %s", primary, alt)
	}

	// A target that checks its destination takes a real domain and refuses a
	// reserved one, so an alt pinned to .invalid silently suppresses findings
	// on exactly the targets that bother to validate.
	assert.Equal(t, "example.com", attack.AltCanary("google.com"))
	assert.Equal(t, "example.net", attack.AltCanary("example.com"))

	// A non-resolving primary keeps a non-resolving alt, so a run can stay
	// clear of real names entirely.
	assert.Equal(t, "detour-alt.invalid", attack.AltCanary("canary.invalid"))
	assert.Equal(t, "detour-alt2.invalid", attack.AltCanary("detour-alt.invalid"))
}

// TestCoverageRecordsRedirectorURLs proves an endpoint that already answers
// with a destination is named, not just counted, so --deep or a manual
// follow-up has something to target instead of a number that was already
// true a run ago.
func TestCoverageRecordsRedirectorURLs(t *testing.T) {
	t.Parallel()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://allowed.lab/")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(plain.Close)

	cfg := config.Config{Canary: testCanary, Rate: 100, Concurrency: 4, Timeout: 3 * time.Second}
	guard := scope.New(cfg.Canary)
	c, err := client.New(cfg, guard)
	require.NoError(t, err)

	eng := attack.New(c, cfg.Canary, "", cfg.Concurrency, nil)

	_, err = eng.Run(context.Background(), []string{redirector.URL + "/", plain.URL + "/"})
	require.NoError(t, err)

	cov := eng.Coverage()

	assert.Equal(t, 1, cov.Redirectors)
	require.Len(t, cov.RedirectorURLs, 1)
	assert.Equal(t, redirector.URL+"/", cov.RedirectorURLs[0])
}
