package attack_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nedlir/detour/internal/attack"
	"github.com/nedlir/detour/internal/checkpoint"
	"github.com/nedlir/detour/internal/client"
	"github.com/nedlir/detour/internal/config"
	"github.com/nedlir/detour/internal/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// baselineValue is the parameter value every test source carries, so a
// handler can tell the plain baseline request from a payload.
const baselineValue = "https://allowed.lab/"

// countingEngine builds an engine against handler, counting every request it gets.
func countingEngine(t *testing.T, handler http.HandlerFunc) (*attack.Engine, *httptest.Server, *atomic.Int64) {
	t.Helper()

	var hits atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)

	cfg := config.Config{Canary: testCanary, Rate: 200, Concurrency: 4, Timeout: 3 * time.Second}
	c, err := client.New(cfg, scope.New(cfg.Canary))
	require.NoError(t, err)

	return attack.New(c, cfg.Canary, "", cfg.Concurrency, nil), srv, &hits
}

// isBaseline reports whether r is the plain request a source starts with.
func isBaseline(r *http.Request) bool {
	return r.URL.Path == "/go" && r.URL.Query().Get("url") == baselineValue &&
		r.Header.Get("X-Forwarded-Host") == ""
}

// redirectToParam is a fully vulnerable endpoint.
func redirectToParam(w http.ResponseWriter, r *http.Request) {
	if dest := r.URL.Query().Get("url"); dest != "" {
		w.Header().Set("Location", dest)
		w.WriteHeader(http.StatusFound)

		return
	}

	w.WriteHeader(http.StatusOK)
}

func cloudflareBlock(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("<title>Attention Required! | Cloudflare</title> Sorry, you have been blocked"))
}

// TestBlockedProbesAreUntestedNotMisses is the false "clean" a WAF used to
// produce: every payload refused by a block page was written to the checkpoint
// as a miss and never tried again. A refused probe must be counted, named by
// vendor, and left unrecorded, so a later run that gets past the block finds
// the bug.
func TestBlockedProbesAreUntestedNotMisses(t *testing.T) {
	t.Parallel()

	var open atomic.Bool

	eng, srv, _ := countingEngine(t, func(w http.ResponseWriter, r *http.Request) {
		if open.Load() {
			redirectToParam(w, r)

			return
		}

		if isBaseline(r) {
			w.WriteHeader(http.StatusOK)

			return
		}

		cloudflareBlock(w)
	})

	path := filepath.Join(t.TempDir(), "waf.ckpt")
	store, err := checkpoint.Open(path)
	require.NoError(t, err)
	eng.SetCheckpoint(store)

	source := srv.URL + "/go?url=" + baselineValue

	findings, err := eng.Run(context.Background(), []string{source})
	require.NoError(t, err)
	assert.Empty(t, findings)

	cov := eng.Coverage()
	assert.Positive(t, cov.Blocked)
	assert.Equal(t, cov.Blocked, cov.BlockedBy["cloudflare"])
	require.NotEmpty(t, cov.BlockedProbes)
	assert.Equal(t, "cloudflare", cov.BlockedProbes[0].Vendor)
	assert.Equal(t, http.StatusForbidden, cov.BlockedProbes[0].Status)
	require.NoError(t, store.Close())

	// The block lifts. A resumed run must retry every refused probe rather
	// than trust a miss that was never observed.
	open.Store(true)

	again, err := checkpoint.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = again.Close() })
	eng.SetCheckpoint(again)

	findings, err = eng.Run(context.Background(), []string{source})
	require.NoError(t, err)
	assert.NotEmpty(t, findings, "probes a waf refused must be retried, not remembered as misses")
}

// TestBare403IsJudgedAgainstTheBaseline separates a refusal from an endpoint
// that refuses everyone. A 403 the baseline did not produce is untested; a 403
// the baseline produced too is the endpoint's own answer.
func TestBare403IsJudgedAgainstTheBaseline(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		baselineStatus int
		wantBlocked    bool
	}{
		{"baseline ok, payloads forbidden", http.StatusOK, true},
		{"everything forbidden", http.StatusForbidden, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			eng, srv, _ := countingEngine(t, func(w http.ResponseWriter, r *http.Request) {
				if isBaseline(r) {
					w.WriteHeader(tt.baselineStatus)

					return
				}

				w.WriteHeader(http.StatusForbidden)
			})

			findings, err := eng.Run(context.Background(), []string{srv.URL + "/go?url=" + baselineValue})
			require.NoError(t, err)
			assert.Empty(t, findings)

			cov := eng.Coverage()
			if tt.wantBlocked {
				assert.Positive(t, cov.BlockedBy["unknown"])
			} else {
				assert.Zero(t, cov.Blocked)
			}
		})
	}
}

// TestBlockedBaselineSkipsTheSource covers the host that is blocked from the
// first request: nothing it answers is the application, so no payload is sent.
func TestBlockedBaselineSkipsTheSource(t *testing.T) {
	t.Parallel()

	eng, srv, hits := countingEngine(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotAcceptable)
	})

	findings, err := eng.Run(context.Background(), []string{srv.URL + "/go?url=" + baselineValue})
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.Equal(t, int64(1), hits.Load(), "only the baseline is sent to a blocked source")

	cov := eng.Coverage()
	assert.Equal(t, 1, cov.Blocked)
	assert.Equal(t, 1, cov.Reachable)
	assert.Zero(t, cov.Params)
}

// TestAuthWalls covers the sources whose first answer is a login wall: they
// are reported as needing a session and cost one request, unless the wall
// carries the source's own parameter (the post-login redirect surface) or the
// operator asked for walls to be attacked anyway.
func TestAuthWalls(t *testing.T) {
	t.Parallel()

	toLogin := func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/users/sign_in", http.StatusFound)
	}

	carrying := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/login?return_to="+r.URL.Query().Get("url"))
		w.WriteHeader(http.StatusFound)
	}

	unauthorized := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}

	tests := []struct {
		name       string
		handler    http.HandlerFunc
		attackAll  bool
		wantWalled bool
		wantReason string
	}{
		{"401", unauthorized, false, true, "status"},
		{"redirect to sign-in", toLogin, false, true, "login redirect"},
		{"redirect carrying the parameter", carrying, false, false, ""},
		{"attack-auth-walls on", toLogin, true, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			eng, srv, hits := countingEngine(t, tt.handler)
			eng.SetAttackAuthWalls(tt.attackAll)

			source := srv.URL + "/go?url=" + baselineValue

			_, err := eng.Run(context.Background(), []string{source})
			require.NoError(t, err)

			walls := eng.Coverage().AuthWalls
			if !tt.wantWalled {
				assert.Empty(t, walls)
				assert.Greater(t, hits.Load(), int64(1), "a source that is not walled is attacked")

				return
			}

			require.Len(t, walls, 1)
			assert.Equal(t, source, walls[0].URL)
			assert.Equal(t, tt.wantReason, walls[0].Reason)
			assert.Equal(t, int64(1), hits.Load(), "a walled source costs one request")
		})
	}
}

// TestAuthWallIsReCheckedOnResume proves a walled source leaves no baseline
// verdict behind: once the operator brings a session (here, the wall lifts),
// a resumed run attacks it instead of trusting the earlier skip.
func TestAuthWallIsReCheckedOnResume(t *testing.T) {
	t.Parallel()

	var open atomic.Bool

	eng, srv, _ := countingEngine(t, func(w http.ResponseWriter, r *http.Request) {
		if !open.Load() {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		redirectToParam(w, r)
	})

	path := filepath.Join(t.TempDir(), "wall.ckpt")
	store, err := checkpoint.Open(path)
	require.NoError(t, err)
	eng.SetCheckpoint(store)

	source := srv.URL + "/go?url=" + baselineValue

	findings, err := eng.Run(context.Background(), []string{source})
	require.NoError(t, err)
	assert.Empty(t, findings)
	require.NoError(t, store.Close())

	open.Store(true)

	again, err := checkpoint.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = again.Close() })
	eng.SetCheckpoint(again)

	findings, err = eng.Run(context.Background(), []string{source})
	require.NoError(t, err)
	assert.NotEmpty(t, findings)
}
