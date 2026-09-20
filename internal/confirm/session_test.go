package confirm_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nedlir/detour/internal/confirm"
	"github.com/nedlir/detour/internal/lab"
	"github.com/nedlir/detour/internal/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testCanary = "canary.invalid"

// requireChrome skips rather than fails. detour is fully usable without a
// browser, so its test suite has to be too.
func requireChrome(t *testing.T) {
	t.Helper()

	if !confirm.Available() {
		t.Skip("no chrome or chromium installed; headless confirmation is opt-in")
	}
}

func newConfirmer(t *testing.T, guard *scope.Guard) *confirm.Confirmer {
	t.Helper()

	return confirm.New(guard, confirm.Options{Canary: testCanary, Timeout: 25 * time.Second})
}

func labServer(t *testing.T) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	return srv
}

// TestVisitConfirmsClientSideClass is the recall gate for the browser stage:
// every one of these returns 200 with no Location, so nothing server-side can
// settle them.
func TestVisitConfirmsClientSideClass(t *testing.T) {
	t.Parallel()
	requireChrome(t)

	srv := labServer(t)
	c := newConfirmer(t, scope.New(testCanary))

	tests := []struct {
		name  string
		probe string
	}{
		{name: "backUrl route guard", probe: "/c01?backUrl=https://" + testCanary + "/x"},
		{name: "location.hash sink", probe: "/c02#https://" + testCanary + "/x"},
		{name: "meta refresh", probe: "/c04?url=https://" + testCanary + "/x"},
		{name: "server redirect still works", probe: "/a07?url=//" + testCanary + "/x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := c.Visit(context.Background(), srv.URL+tt.probe)
			require.NoError(t, err)
			assert.True(t, result.Confirmed, "expected a navigation to the canary")
			assert.Contains(t, result.FinalURL, testCanary)
			assert.NotEmpty(t, result.Chain)
		})
	}
}

func TestVisitLeavesDecoysAlone(t *testing.T) {
	t.Parallel()
	requireChrome(t)

	srv := labServer(t)
	c := newConfirmer(t, scope.New(testCanary))

	tests := []struct {
		name  string
		probe string
	}{
		{name: "exact allowlist", probe: "/decoy/allowlist?backUrl=https://" + testCanary + "/x"},
		{name: "static redirect", probe: "/decoy/static"},
		{name: "reflection without navigation", probe: "/decoy/reflect?url=https://" + testCanary + "/x"},
		{name: "correctly guarded bundle", probe: "/decoy/guarded?next=https://" + testCanary + "/x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := c.Visit(context.Background(), srv.URL+tt.probe)
			require.NoError(t, err)
			assert.False(t, result.Confirmed, "decoy must not confirm")
			assert.Empty(t, result.FinalURL)
		})
	}
}

// TestOffScopeRequestIsAbortedButCaptured is the safety rule, tested against
// a server that really would answer. localhost and 127.0.0.1 are the same
// address but different hostnames, which is what lets one be in scope and the
// other not.
func TestOffScopeRequestIsAbortedButCaptured(t *testing.T) {
	t.Parallel()
	requireChrome(t)

	var hits atomic.Int64

	offScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(offScope.Close)

	srv := labServer(t)
	target := srv.URL + "/c01?backUrl=" + localhostURL(t, offScope.URL) + "/x"

	guard, err := scope.Parse([]string{"127.0.0.1"}, testCanary)
	require.NoError(t, err)

	result, err := confirm.New(guard, confirm.Options{
		Canary:  testCanary,
		Timeout: 25 * time.Second,
	}).Visit(context.Background(), target)
	require.NoError(t, err)

	assert.Zero(t, hits.Load(), "an off-scope request must never leave the browser")
	assert.NotEmpty(t, result.Blocked, "the attempt is recorded even though it was refused")
	assert.Contains(t, result.Blocked[0], "localhost")
}

// TestInScopeRequestIsAllowed is the control for the test above: with the same
// host in scope, the request goes through. Without this, a block could be an
// accident rather than the guard doing its job.
func TestInScopeRequestIsAllowed(t *testing.T) {
	t.Parallel()
	requireChrome(t)

	var hits atomic.Int64

	reachable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(reachable.Close)

	srv := labServer(t)
	target := srv.URL + "/c01?backUrl=" + localhostURL(t, reachable.URL) + "/x"

	guard, err := scope.Parse([]string{"127.0.0.1", "localhost"}, testCanary)
	require.NoError(t, err)

	_, err = confirm.New(guard, confirm.Options{
		Canary:  testCanary,
		Timeout: 25 * time.Second,
	}).Visit(context.Background(), target)
	require.NoError(t, err)

	assert.Positive(t, hits.Load(), "an in-scope request is not blocked")
}

// localhostURL rewrites a test server URL onto the localhost name, so the same
// address can be addressed by a host the scope guard treats differently.
func localhostURL(t *testing.T, raw string) string {
	t.Helper()

	parsed, err := url.Parse(raw)
	require.NoError(t, err)

	return "http://localhost:" + parsed.Port()
}

func TestVisitWithoutChromeIsACleanError(t *testing.T) {
	c := confirm.New(scope.New(testCanary), confirm.Options{
		Canary:     testCanary,
		ChromePath: "",
	})

	t.Setenv("DETOUR_CHROME", "/nonexistent/chrome")

	_, err := c.Visit(context.Background(), "https://example.invalid/")
	require.ErrorIs(t, err, confirm.ErrChromeNotFound)
}
