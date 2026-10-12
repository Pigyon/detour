package confirm_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nedlir/detour/internal/confirm"
	"github.com/nedlir/detour/internal/lab"
	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func candidate(technique, source, param, payload string) model.Finding {
	f := model.NewFinding()
	f.TechniqueID = technique
	f.Mechanism = "js"
	f.Payload = payload
	f.Verdict = model.VerdictCandidate
	f.Candidate = model.NewNavigationCandidate(source, model.RepresentationJSExpression)
	f.Candidate.ParamName = param

	return f
}

// TestConfirmPromotesClientSideCandidates is the whole point of the stage: a
// finding no server-side check could settle becomes confirmed.
func TestConfirmPromotesClientSideCandidates(t *testing.T) {
	t.Parallel()
	requireChrome(t)

	srv := labServer(t)
	c := newConfirmer(t, scope.New(testCanary))

	findings := []model.Finding{
		candidate("OR-C01", srv.URL+"/c01", "backUrl", "https://{{canary}}/x"),
		candidate("OR-C02", srv.URL+"/c02", "", "https://{{canary}}/x"),
	}

	promoted, summary, err := c.Confirm(context.Background(), findings)
	require.NoError(t, err)
	require.Len(t, promoted, 2)
	assert.Equal(t, 2, summary.Confirmed)
	assert.Equal(t, 2, summary.Attempted)

	for _, f := range promoted {
		assert.Equal(t, model.VerdictConfirmed, f.Verdict)
		assert.True(t, f.Capabilities.BrowserConfirmed)
		assert.True(t, f.Capabilities.RedirectExternal)
		assert.Equal(t, f.Capabilities, f.Candidate.Capabilities, "the candidate carries the same capabilities")
		assert.Contains(t, f.ProbeURL, srv.URL)
	}
}

// TestConfirmGuessesAnUnresolvedParamFromTheSourceURL is the case the JS
// stage leaves stuck: a sink whose input the static tracer could not name,
// so ParamName is empty. Confirm still has something to try: the query
// parameter the source URL already carries.
func TestConfirmGuessesAnUnresolvedParamFromTheSourceURL(t *testing.T) {
	t.Parallel()
	requireChrome(t)

	srv := labServer(t)
	c := newConfirmer(t, scope.New(testCanary))

	f := candidate("OR-C01", srv.URL+"/c01?backUrl=placeholder", "", "https://{{canary}}/x")

	promoted, summary, err := c.Confirm(context.Background(), []model.Finding{f})
	require.NoError(t, err)
	require.Len(t, promoted, 1)
	assert.Equal(t, 1, summary.Confirmed)
	assert.Equal(t, model.VerdictConfirmed, promoted[0].Verdict)
	assert.True(t, promoted[0].Capabilities.BrowserConfirmed)
}

// TestConfirmLeavesUnprovenCandidatesAlone pins the honesty rule in the other
// direction: a browser that does not reproduce something is not proof the
// finding was wrong.
func TestConfirmLeavesUnprovenCandidatesAlone(t *testing.T) {
	t.Parallel()
	requireChrome(t)

	srv := labServer(t)
	c := newConfirmer(t, scope.New(testCanary))

	findings := []model.Finding{
		candidate("OR-C01", srv.URL+"/decoy/allowlist", "backUrl", "https://{{canary}}/x"),
	}

	promoted, summary, err := c.Confirm(context.Background(), findings)
	require.NoError(t, err)
	require.Len(t, promoted, 1)
	assert.Equal(t, model.VerdictCandidate, promoted[0].Verdict, "still a candidate, never dropped")
	assert.False(t, promoted[0].Capabilities.BrowserConfirmed)
	assert.Zero(t, summary.Confirmed)
	assert.Equal(t, 1, summary.Attempted)
}

func TestConfirmSkipsFindingsABrowserCannotSettle(t *testing.T) {
	t.Parallel()
	requireChrome(t)

	c := newConfirmer(t, scope.New(testCanary))

	findings := []model.Finding{
		candidate("OR-F09", "https://site.lab/page", "", ""),
		candidate("OR-C03", "https://site.lab/page", "", ""),
	}

	promoted, summary, err := c.Confirm(context.Background(), findings)
	require.NoError(t, err)
	assert.Len(t, promoted, 2)
	assert.Equal(t, 2, summary.Skipped)
	assert.Zero(t, summary.Attempted)
}

// TestConfirmCookieGatedBackURL exercises the auth-required endpoint: the
// same probe reaches a sink only when the session cookie is set, and the
// cookie is only ever set for an in-scope host.
func TestConfirmCookieGatedBackURL(t *testing.T) {
	t.Parallel()
	requireChrome(t)

	srv := labServer(t)
	probe := srv.URL + "/auth/back?backUrl=https://" + testCanary + "/x"

	unauthed, err := confirm.New(scope.New(testCanary), confirm.Options{
		Canary:  testCanary,
		Timeout: 25 * time.Second,
	}).Visit(context.Background(), probe)
	require.NoError(t, err)
	assert.False(t, unauthed.Confirmed, "no session, no sink")

	authed, err := confirm.New(scope.New(testCanary), confirm.Options{
		Canary:  testCanary,
		Timeout: 25 * time.Second,
		Cookies: []*http.Cookie{{ //nolint:gosec // G124: replaying an operator cookie into a local lab.
			Name:  lab.SessionCookieName,
			Value: lab.SessionCookieValue,
			Path:  "/",
		}},
	}).Visit(context.Background(), probe)
	require.NoError(t, err)
	assert.True(t, authed.Confirmed, "the session cookie reaches the gated sink")
	assert.Contains(t, authed.FinalURL, testCanary)
}

// TestConfirmDoesNotSendCookiesOffScope keeps credentials inside the boundary.
func TestConfirmDoesNotSendCookiesOffScope(t *testing.T) {
	t.Parallel()
	requireChrome(t)

	gotCookie := make(chan string, 4)

	offScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie <- r.Header.Get("Cookie")

		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(offScope.Close)

	guard, err := scope.Parse([]string{"127.0.0.1"}, testCanary)
	require.NoError(t, err)

	srv := labServer(t)

	_, err = confirm.New(guard, confirm.Options{
		Canary:  testCanary,
		Timeout: 25 * time.Second,
		//nolint:gosec // G124: the point of this test is that the cookie never leaves.
		Cookies: []*http.Cookie{{Name: "session", Value: "secret", Path: "/"}},
	}).Visit(context.Background(), srv.URL+"/c01?backUrl="+localhostURL(t, offScope.URL)+"/x")
	require.NoError(t, err)

	select {
	case seen := <-gotCookie:
		t.Fatalf("off-scope host was contacted at all, with cookie %q", seen)
	default:
	}
}

// TestConfirmWritesArtifacts covers both artifact cases. A HAR is written for
// every confirmed finding. A screenshot is written when one can physically be
// taken, which a server-side redirect allows and an immediate client-side one
// does not: the destination never loads and the initiating page has already
// left.
func TestConfirmWritesArtifacts(t *testing.T) {
	t.Parallel()
	requireChrome(t)

	tests := []struct {
		name    string
		finding model.Finding
		wantPNG bool
		wantHAR bool
	}{
		{
			name:    "server side redirect is photographable",
			finding: candidate("OR-A07", "", "", ""),
			wantPNG: true,
			wantHAR: true,
		},
		{
			name:    "immediate client side redirect leaves no page to picture",
			finding: candidate("OR-C01", "", "backUrl", "https://{{canary}}/x"),
			wantPNG: false,
			wantHAR: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := labServer(t)
			dir := t.TempDir()

			f := tt.finding
			if f.TechniqueID == "OR-A07" {
				f.ProbeURL = srv.URL + "/a07?url=//" + testCanary + "/x"
			} else {
				f.Candidate.SourceURL = srv.URL + "/c01"
			}

			c := confirm.New(scope.New(testCanary), confirm.Options{
				Canary:      testCanary,
				Timeout:     25 * time.Second,
				ArtifactDir: dir,
			})

			_, summary, err := c.Confirm(context.Background(), []model.Finding{f})
			require.NoError(t, err)
			require.Equal(t, 1, summary.Confirmed)

			assert.Equal(t, tt.wantHAR, hasExt(t, dir, ".har"), "har")
			assert.Equal(t, tt.wantPNG, hasExt(t, dir, ".png"), "screenshot")
		})
	}
}

func hasExt(t *testing.T, dir, ext string) bool {
	t.Helper()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	for _, e := range entries {
		if filepath.Ext(e.Name()) == ext {
			return true
		}
	}

	return false
}

func TestConfirmWithoutChromeReturnsFindingsUnchanged(t *testing.T) {
	t.Setenv("DETOUR_CHROME", "/nonexistent/chrome")

	findings := []model.Finding{candidate("OR-C01", "https://site.lab/c01", "backUrl", "https://{{canary}}/x")}

	c := confirm.New(scope.New(testCanary), confirm.Options{Canary: testCanary})

	out, summary, err := c.Confirm(context.Background(), findings)
	require.ErrorIs(t, err, confirm.ErrChromeNotFound)
	assert.Equal(t, findings, out, "the findings survive a missing browser")
	assert.Zero(t, summary.Attempted)
}
