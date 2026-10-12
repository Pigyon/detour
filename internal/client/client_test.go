package client_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nedlir/detour/internal/client"
	"github.com/nedlir/detour/internal/config"
	"github.com/nedlir/detour/internal/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, cfg config.Config, hosts ...string) *client.Client {
	t.Helper()

	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Second
	}

	if cfg.Rate == 0 {
		cfg.Rate = 50
	}

	lines := append([]string{}, hosts...)
	guard, err := scope.Parse(lines, config.DefaultCanary)
	require.NoError(t, err)

	c, err := client.New(cfg, guard)
	require.NoError(t, err)

	return c
}

func TestDoAttachesCredentialsInScope(t *testing.T) {
	t.Parallel()

	var gotAuth atomic.Value

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))

		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)

	host := mustHost(t, srv.URL)
	c := newTestClient(t, config.Config{
		Headers: []string{"Authorization: Bearer secret"},
		Rate:    50,
		Timeout: time.Second,
	}, host)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	resp, err := c.Do(context.Background(), req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	assert.Equal(t, "Bearer secret", gotAuth.Load())
}

func TestDoStripsCredentialsAndSkipsOffScope(t *testing.T) {
	t.Parallel()

	var hits atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	c := newTestClient(t, config.Config{
		Headers: []string{"Authorization: Bearer secret"},
		Rate:    50,
		Timeout: time.Second,
	}, "in-scope.example")

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer secret")

	resp, err := c.Do(context.Background(), req)
	if resp != nil {
		t.Cleanup(func() { _ = resp.Body.Close() })
	}

	require.ErrorIs(t, err, scope.ErrOutOfScope)
	assert.Equal(t, int64(0), hits.Load())
	assert.Empty(t, req.Header.Get("Authorization"))
}

func TestDoNeverContactsCanary(t *testing.T) {
	t.Parallel()

	guard := scope.New(config.DefaultCanary)
	c, err := client.New(config.Config{Rate: 50, Timeout: time.Second}, guard)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"https://"+config.DefaultCanary+"/landed",
		nil,
	)
	require.NoError(t, err)

	resp, err := c.Do(context.Background(), req)
	if resp != nil {
		t.Cleanup(func() { _ = resp.Body.Close() })
	}

	require.ErrorIs(t, err, scope.ErrCanary)
}

func TestDoDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://evil.example/")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	host := mustHost(t, srv.URL)
	c := newTestClient(t, config.Config{Rate: 50, Timeout: time.Second}, host)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	resp, err := c.Do(context.Background(), req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "https://evil.example/", resp.Header.Get("Location"))
}

func TestDoRespectsContextCancel(t *testing.T) {
	t.Parallel()

	cfg := config.Config{Rate: 0.01, Timeout: 5 * time.Second}
	guard := scope.New(config.DefaultCanary)
	c, err := client.New(cfg, guard)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	require.NoError(t, err)

	resp, err := c.Do(ctx, req)
	if resp != nil {
		t.Cleanup(func() { _ = resp.Body.Close() })
	}

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestNetscapeCookies(t *testing.T) {
	t.Parallel()

	var gotCookie atomic.Value

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("sid")
		if err == nil {
			gotCookie.Store(cookie.Value)
		}

		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	host := mustHost(t, srv.URL)
	path := filepath.Join(t.TempDir(), "cookies.txt")
	body := host + "\tFALSE\t/\tFALSE\t0\tsid\tlab-session\n"
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	c := newTestClient(t, config.Config{
		CookiesFile: path,
		Rate:        50,
		Timeout:     time.Second,
	}, host)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	resp, err := c.Do(context.Background(), req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	assert.Equal(t, "lab-session", gotCookie.Load())
}

func mustHost(t *testing.T, rawURL string) string {
	t.Helper()

	host, err := scope.HostOf(rawURL)
	require.NoError(t, err)

	return host
}

// TestDoReturnsResponseWithUnparseableLocation is a regression for a miss that
// hid a whole technique class.
//
// http.Client parses the Location header before it consults CheckRedirect, so
// a response carrying a Location that net/url refuses came back as a transport
// error and the response was lost. Every payload in the Spring-bracket and
// delimiter-stuffing families is designed to produce exactly such a Location,
// so the engine reported those endpoints clean.
func TestDoReturnsResponseWithUnparseableLocation(t *testing.T) {
	t.Parallel()

	const hostile = "https://canary.invalid[@allowed.example/"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", hostile)
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	c := newTestClient(t, config.Config{}, hostOf(t, srv.URL))

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	resp, err := c.Do(context.Background(), req)
	require.NoError(t, err, "a Location net/url refuses must not lose the response")

	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, hostile, resp.Header.Get("Location"))
}

// TestDoDoesNotThrottleOnOriginFailure keeps retrying and slowing down as
// separate decisions. A 502 is the origin failing to reach something further
// back, which is what a URL-fetching endpoint returns for a destination it
// cannot retrieve. Treating it as pushback collapsed the per-host limiter to
// its floor and stalled the run.
func TestDoDoesNotThrottleOnOriginFailure(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)

	host := hostOf(t, srv.URL)
	c := newTestClient(t, config.Config{}, host)
	before := c.RateFor(host)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	drain(c.Do(context.Background(), req))

	assert.InEpsilon(t, before, c.RateFor(host), 1e-9, "an origin failure must not slow the host")
}

// TestDoThrottlesOnPushback is the other half: a host that says it wants less
// traffic still gets less.
func TestDoThrottlesOnPushback(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)

	host := hostOf(t, srv.URL)
	c := newTestClient(t, config.Config{}, host)
	before := c.RateFor(host)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	drain(c.Do(context.Background(), req))

	assert.Less(t, c.RateFor(host), before, "pushback must slow the host")
}

// hostOf is the host of a test server URL, which is what the scope guard and
// the per-host limiter are both keyed on.
func hostOf(t *testing.T, raw string) string {
	t.Helper()

	parsed, err := url.Parse(raw)
	require.NoError(t, err)

	return parsed.Hostname()
}

// drain closes a response body the test does not read, so the linter's
// accounting stays honest.
func drain(resp *http.Response, _ error) {
	if resp != nil {
		_ = resp.Body.Close()
	}
}

// TestPushbackSlowsOncePerRequest keeps one bad moment from pinning a host at
// the rate floor. Halving on every retry of the same request divides the rate
// by sixteen.
func TestPushbackSlowsOncePerRequest(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)

	host := hostOf(t, srv.URL)
	c := newTestClient(t, config.Config{Rate: 8}, host)
	before := c.RateFor(host)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	drain(c.Do(context.Background(), req))

	assert.InEpsilon(t, before/2, c.RateFor(host), 1e-9,
		"one request that is pushed back must halve the rate once, not once per attempt")
}

// TestSustainedPushbackDoesNotCollapseTheRate is the case a WAF produces.
//
// Halving once per request is not gentle: a host that answers 403 to
// everything takes a requested rate to the 0.1 floor in thirteen requests,
// after which the run spends ten seconds per request and looks hung. One URL
// against such a host spent fifteen minutes on eighty-eight requests.
func TestSustainedPushbackDoesNotCollapseTheRate(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	host := hostOf(t, srv.URL)
	c := newTestClient(t, config.Config{Rate: 64}, host)
	before := c.RateFor(host)

	for range 20 {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		require.NoError(t, err)

		drain(c.Do(context.Background(), req))
	}

	assert.InEpsilon(t, before/2, c.RateFor(host), 1e-9,
		"twenty refusals in a row must cost one rate cut, not twenty")
}

// TestForbiddenSlowsWithoutRetrying is the other half: a 403 is a terminal
// answer worth no retry, and still a request to send less traffic.
func TestForbiddenSlowsWithoutRetrying(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	host := hostOf(t, srv.URL)
	c := newTestClient(t, config.Config{Rate: 8}, host)
	before := c.RateFor(host)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	drain(c.Do(context.Background(), req))

	assert.Equal(t, int64(1), attempts.Load(), "a 403 is terminal and must not be retried")
	assert.Less(t, c.RateFor(host), before, "a 403 is still pushback")
}

// TestHostGivesUpAfterSustainedFloorPushback is the multi-hour-grind case: a
// WAF that never stops refusing must not keep the run paying ten seconds a
// request against it forever.
func TestHostGivesUpAfterSustainedFloorPushback(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	host := hostOf(t, srv.URL)
	c := newTestClient(t, config.Config{Rate: 64}, host)

	// ForceSlow drives the same state transition sustained pushback over a
	// real run would, without blocking on the real rate.Limiter once the
	// rate has collapsed: enough halvings to reach the floor, then enough
	// floor-rate pushbacks to cross the give-up threshold.
	for range 20 {
		c.ForceSlow(host)
	}

	assert.InEpsilon(t, client.MinRate, c.RateFor(host), 1e-9, "sustained refusal must reach the floor")
	assert.True(t, c.HasGivenUpOn(host), "a host still refusing at the floor must be given up on")
}

// TestGivingUpStopsSendingRequests proves the give-up is not just a label: a
// given-up host must stop receiving traffic, which is the entire point.
func TestGivingUpStopsSendingRequests(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	host := hostOf(t, srv.URL)
	c := newTestClient(t, config.Config{Rate: 64}, host)

	for range 20 {
		c.ForceSlow(host)
	}

	require.True(t, c.HasGivenUpOn(host), "precondition: the host must have given up")

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	resp, err := c.Do(context.Background(), req)
	drain(resp, nil)

	require.ErrorIs(t, err, client.ErrHostGivenUp, "a given-up host must fail fast with the sentinel error")
	assert.Equal(t, int64(0), attempts.Load(), "a given-up host must receive no requests at all")
}

// TestHostRecoversAfterSuccess is the other half: a host that answers
// normally again is not settled, and must not stay pinned at the floor.
func TestHostRecoversAfterSuccess(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	host := hostOf(t, srv.URL)
	c := newTestClient(t, config.Config{Rate: 64}, host)
	base := c.RateFor(host)

	for range 5 {
		c.ForceSlow(host)
	}

	collapsed := c.RateFor(host)
	require.Less(t, collapsed, base, "precondition: sustained refusal must have slowed the host")

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	c.BackdateCooldowns(host, client.RecoverCooldown)
	drain(c.Do(context.Background(), req))

	assert.Greater(t, c.RateFor(host), collapsed, "a success must raise the rate back up")
	assert.False(t, c.HasGivenUpOn(host), "a success must clear any pending give-up")
}

// TestRecoveryNeverExceedsTheConfiguredRate keeps recovery from overshooting
// what the operator asked for in the first place.
func TestRecoveryNeverExceedsTheConfiguredRate(t *testing.T) {
	t.Parallel()

	host := "recovery-ceiling.invalid"
	c := newTestClient(t, config.Config{Rate: 8}, host)
	base := c.RateFor(host)

	for range 10 {
		c.ForceRecover(host)
	}

	assert.InEpsilon(t, base, c.RateFor(host), 1e-9, "recovery must not exceed the configured rate")
}

// TestRealSustainedCollapseEndsInGiveUp is the genuine proof the other
// give-up tests are a fast stand-in for: every one of them uses ForceSlow
// to skip the real rate.Limiter.Wait a collapsed host actually blocks on,
// which proves the state machine but not that a real sequence of requests
// against a real host reaches the same place.
//
// Rate starts one halving above the floor on purpose: reaching the floor
// through a real halving, then five more real floor-rate waits to cross the
// give-up threshold, is the minimum real time the actual collapse takes.
// Starting any higher would multiply this by however many halvings it
// takes to get there, for no more proof than this already gives.
//
//nolint:paralleltest // deliberately slow and timing-sensitive; must not share a scheduler with others
func TestRealSustainedCollapseEndsInGiveUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	host := hostOf(t, srv.URL)
	c := newTestClient(t, config.Config{Rate: 2 * client.MinRate}, host)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	for !c.HasGivenUpOn(host) {
		require.NoError(t, ctx.Err(), "the real collapse did not reach give-up within the time budget")
		drain(c.Do(ctx, req))
	}

	// The promise a given-up host makes is a fast failure, not just an
	// eventual one. Proving that needs a real clock: this is the one place
	// in the suite that checks actual elapsed time rather than call counts.
	start := time.Now()
	resp, doErr := c.Do(ctx, req)

	drain(resp, nil)

	elapsed := time.Since(start)

	require.ErrorIs(t, doErr, client.ErrHostGivenUp)
	assert.Less(t, elapsed, time.Second,
		"a given-up host must fail immediately, not after another floor-rate wait")
}
