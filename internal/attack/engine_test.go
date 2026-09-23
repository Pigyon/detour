package attack_test

import (
	"context"
	"net/http/httptest"
	"path/filepath"
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
