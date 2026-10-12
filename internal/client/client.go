// Package client is the shared HTTP client with scope, auth, and rate limits.
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sync"
	"syscall"
	"time"

	"github.com/nedlir/detour/internal/config"
	"github.com/nedlir/detour/internal/scope"
	"golang.org/x/time/rate"
)

const (
	maxRetries   = 3
	minRate      = 0.1
	backoffBase  = 200 * time.Millisecond
	defaultBurst = 1

	// slowCooldown is the shortest wall-clock gap between two rate cuts for
	// one host.
	//
	// Halving once per request sounds gentle and is not: a host that answers
	// 403 to everything, which is what a WAF that has made up its mind does,
	// takes a requested 500 rps to the 0.1 floor in thirteen requests. The
	// run then spends ten seconds per request and looks hung. One URL against
	// such a host took fifteen minutes for eighty-eight requests. Pacing the
	// cut by time instead keeps the adaptation and bounds how fast it can
	// collapse.
	slowCooldown = 5 * time.Second

	// maxFloorPushbacks is how many pushbacks a host gets once it is already
	// at the rate floor before the client gives up on it entirely.
	//
	// The floor alone does not bound a run: a host that never stops saying no
	// still costs ten seconds per request forever, and a target with hundreds
	// of remaining URLs behind it turns a run into a multi-hour grind with
	// nothing to show. A host that is still refusing after this many floor-rate
	// attempts is settled, not slow, and the rest of its queue is better spent
	// elsewhere.
	maxFloorPushbacks = 5

	// recoverCooldown is the shortest wall-clock gap between two rate
	// restorations for one host. Longer than slowCooldown on purpose: a host
	// recovers on the strength of a success, and flapping the rate on every
	// other response would undo the pacing slow() exists for.
	recoverCooldown = 30 * time.Second
)

// ErrHostGivenUp is returned when a host has been pushed back often enough,
// at the rate floor, that the client stops sending it requests for the rest
// of the run.
//
// Callers see this exactly like any other failed request: the attack engine
// already treats a Do error as unanswered rather than a miss, so a given-up
// host is skipped, not recorded as clean.
var ErrHostGivenUp = errors.New("client: host gave up after sustained pushback at the rate floor")

// Client issues scoped, credential-safe HTTP requests and never follows redirects.
type Client struct {
	transport http.RoundTripper
	guard     *scope.Guard
	// creds is the live header and cookie set, swappable by a background
	// refresh while requests are in flight.
	creds *credentials
	// inline and inlineHeaders are the --cookie and --header halves, preserved
	// across every reload of the file-backed halves.
	inline        []*http.Cookie
	inlineHeaders http.Header
	// cookiesFile, headersFile, refresh, credsRefreshCmd, and the auth-check
	// fields drive keeping a short-lived session fresh and noticing when it
	// dies. See auth_watch.go.
	cookiesFile     string
	headersFile     string
	refresh         time.Duration
	credsRefreshCmd string
	authCheck       string
	authExpect      string
	authRequired    bool
	rate            rate.Limit
	delay           time.Duration
	timeout         time.Duration
	limiters        sync.Map
	// inFlight bounds how many requests are on the wire at once.
	//
	// The bound belongs here rather than in a worker pool, because this is the
	// one place every request passes through. A pool over source URLs cannot
	// enforce it: one URL fans out into dozens of payloads, so a limit on
	// sources bounds goroutines and not traffic, and --concurrency then does
	// nothing at all for a single URL.
	inFlight chan struct{}
}

// New builds a client from cfg. Credentials are attached only after the guard
// allows the host.
func New(cfg config.Config, guard *scope.Guard) (*Client, error) {
	if guard == nil {
		return nil, errors.New("nil scope guard")
	}

	inlineHeaders, err := config.ParseHeaders(cfg.Headers)
	if err != nil {
		return nil, err
	}

	transport, err := newTransport(cfg.Proxy)
	if err != nil {
		return nil, err
	}

	limit := rate.Limit(cfg.Rate)
	if limit <= 0 {
		limit = rate.Limit(5)
	}

	c := &Client{
		transport:       transport,
		timeout:         cfg.Timeout,
		guard:           guard,
		creds:           &credentials{},
		inline:          parseCookieHeader(cfg.Cookie),
		inlineHeaders:   inlineHeaders,
		cookiesFile:     cfg.CookiesFile,
		headersFile:     cfg.HeadersFile,
		refresh:         cfg.SessionRefresh,
		credsRefreshCmd: cfg.CredsRefreshCmd,
		authCheck:       cfg.AuthCheck,
		authExpect:      cfg.AuthCheckExpect,
		authRequired:    cfg.AuthCheckRequired,
		rate:            limit,
		delay:           cfg.Delay,
	}

	// The initial credential set comes from the same reload path the refresh
	// uses, so a bad --cookies-file or --headers-file is caught here at startup
	// rather than silently on the first refresh tick.
	if err := c.reloadCredentials(); err != nil {
		return nil, err
	}

	return c, nil
}

func newTransport(proxy string) (*http.Transport, error) {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("http.DefaultTransport is not *http.Transport")
	}

	transport := base.Clone()
	if proxy == "" {
		return transport, nil
	}

	proxyURL, err := url.Parse(proxy)
	if err != nil {
		return nil, fmt.Errorf("parsing proxy url: %w", err)
	}

	transport.Proxy = http.ProxyURL(proxyURL)

	return transport, nil
}

// Do sends req if the host is in scope. The canary and off-scope hosts never
// receive a request; credentials are stripped whenever the host is not allowed.
func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if req.URL == nil {
		return nil, errors.New("request has no url")
	}

	host := req.URL.Hostname()
	if err := c.guard.Check(host); err != nil {
		stripCredentials(req)
		return nil, err
	}

	headers, cookies := c.creds.snapshot()
	applyCredentials(req, headers, cookies)

	// The rate wait happens before the in-flight slot is taken, not after. A
	// goroutine blocked on a collapsed host's limiter is not a request on the
	// wire, and holding the slot across that wait let one bad host starve
	// --concurrency for every other host in the same run.
	if err := c.wait(ctx, host); err != nil {
		return nil, err
	}

	release, err := c.acquire(ctx)
	if err != nil {
		return nil, err
	}

	defer release()

	return c.doWithRetry(ctx, req)
}

// acquire takes an in-flight slot, returning the function that gives it back.
func (c *Client) acquire(ctx context.Context) (func(), error) {
	if c.inFlight == nil {
		return func() {}, nil
	}

	select {
	case c.inFlight <- struct{}{}:
		return func() { <-c.inFlight }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for an in-flight slot: %w", ctx.Err())
	}
}

func (c *Client) wait(ctx context.Context, host string) error {
	limit := c.limiterFor(host)

	if limit.hasGivenUp() {
		return fmt.Errorf("%s: %w", host, ErrHostGivenUp)
	}

	if err := limit.limiter.Wait(ctx); err != nil {
		return fmt.Errorf("rate limiter: %w", err)
	}

	if c.delay <= 0 {
		return nil
	}

	timer := time.NewTimer(c.delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// hostLimit is one host's pacing: its limiter, the rate it started at, and
// when it was last moved.
type hostLimit struct {
	limiter *rate.Limiter
	base    rate.Limit

	mu          sync.Mutex
	lastSlow    time.Time
	lastRecover time.Time
	// floorPushbacks counts pushbacks received while already at the rate
	// floor. A success anywhere above the floor resets it: the host only
	// gives up for sustained refusal once nothing is left to slow down for.
	floorPushbacks int
	givenUp        bool
}

// slow halves the host's rate, at most once per slowCooldown, and gives up on
// the host once it has refused this many times running at the floor.
func (h *hostLimit) slow(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.limiter.Limit() <= minRate {
		h.floorPushbacks++

		if h.floorPushbacks >= maxFloorPushbacks {
			h.givenUp = true
		}
	}

	if !h.lastSlow.IsZero() && now.Sub(h.lastSlow) < slowCooldown {
		return
	}

	h.lastSlow = now

	next := h.limiter.Limit() / 2
	if next < minRate {
		next = minRate
	}

	h.limiter.SetLimit(next)
}

// recover raises the host's rate after a success, at most once per
// recoverCooldown, and clears any pending give-up: an answer, even a slow
// one, means the host is not settled after all.
func (h *hostLimit) recover(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.floorPushbacks = 0
	h.givenUp = false

	if h.limiter.Limit() >= h.base {
		return
	}

	if !h.lastRecover.IsZero() && now.Sub(h.lastRecover) < recoverCooldown {
		return
	}

	h.lastRecover = now

	next := h.limiter.Limit() * 2
	if next > h.base {
		next = h.base
	}

	h.limiter.SetLimit(next)
}

// hasGivenUp reports whether the host has been given up on.
func (h *hostLimit) hasGivenUp() bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.givenUp
}

func (c *Client) limiterFor(host string) *hostLimit {
	if got, ok := c.limiters.Load(host); ok {
		limit, ok := got.(*hostLimit)
		if ok {
			return limit
		}
	}

	created := &hostLimit{limiter: rate.NewLimiter(c.rate, defaultBurst), base: c.rate}
	actual, _ := c.limiters.LoadOrStore(host, created)

	limit, ok := actual.(*hostLimit)
	if !ok {
		return created
	}

	return limit
}

func (c *Client) doWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	var (
		lastErr error
		slowed  bool
	)

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			if err := sleepBackoff(ctx, attempt); err != nil {
				return nil, err
			}

			// A retry is another request and has to take a token like any
			// other. Backoff alone let four attempts leave in 1.4s at a
			// configured one-per-two-seconds, against exactly the host that
			// had just asked for less traffic.
			if err := c.wait(ctx, req.URL.Hostname()); err != nil {
				return nil, err
			}
		}

		resp, err := c.roundTrip(ctx, req)
		if err != nil {
			lastErr = err

			if ctx.Err() != nil {
				return nil, ctx.Err()
			}

			// A refused connection or an unknown name is settled: the host
			// said no, or does not exist. Retrying it four times with backoff
			// turned an unreachable target into a minute per URL and produced
			// the same answer each time.
			if terminalTransportError(err) {
				return nil, fmt.Errorf("request failed: %w", err)
			}

			continue
		}

		// Pushback is judged before the retry decision. A 403 is a terminal
		// answer worth no retry, and it is still the host asking for less
		// traffic, so it has to be seen here or the branch is unreachable.
		//
		// Once per request, not once per attempt. Halving the rate on every
		// retry of the same request divides it by sixteen, which pins a host
		// at the floor for the rest of the run over one bad moment.
		if isPushback(resp.StatusCode) {
			if !slowed {
				slowed = true

				c.slowHost(req.URL.Hostname())
			}
		} else {
			// Any non-pushback answer, even one asking for a retry, means the
			// host is not the one refusing traffic right now. A floor rate is
			// only still earned by a host that keeps saying no.
			c.recoverHost(req.URL.Hostname())
		}

		if !shouldRetry(resp.StatusCode) {
			return resp, nil
		}

		lastErr = fmt.Errorf("status %d", resp.StatusCode)
		drainAndClose(resp.Body)
	}

	return nil, fmt.Errorf("request failed: %w", lastErr)
}

// roundTrip sends one request without net/http's redirect handling.
//
// http.Client parses the Location header before it consults CheckRedirect, so
// a response carrying a Location that net/url refuses is returned to the
// caller as a transport error and the response is lost. That is the entire
// Spring-bracket and delimiter-stuffing class: the whole point of those
// payloads is a Location net/url will not parse. detour resolves every
// destination itself, so the redirect loop has nothing to offer and is
// bypassed here.
func (c *Client) roundTrip(ctx context.Context, req *http.Request) (*http.Response, error) {
	cancel := context.CancelFunc(func() {})

	if c.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
	}

	resp, err := c.transport.RoundTrip(req.Clone(ctx))
	if err != nil {
		cancel()

		return nil, fmt.Errorf("round trip: %w", err)
	}

	// The deadline has to outlive this function, because the body is read by
	// the caller. Cancelling here would close it first, so cancellation is
	// tied to the body instead.
	resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}

	return resp, nil
}

// cancelBody releases the request context once the caller is done with the
// response.
type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
	once   sync.Once
}

func (b *cancelBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.cancel)

	if err != nil {
		return fmt.Errorf("closing body: %w", err)
	}

	return nil
}

func (c *Client) slowHost(host string) {
	c.limiterFor(host).slow(time.Now())
}

func (c *Client) recoverHost(host string) {
	c.limiterFor(host).recover(time.Now())
}

func shouldRetry(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable:
		return true
	default:
		return false
	}
}

// terminalTransportError reports whether retrying could plausibly change the
// outcome.
func terminalTransportError(err error) bool {
	if dnsErr, ok := errors.AsType[*net.DNSError](err); ok {
		return !dnsErr.IsTemporary
	}

	// A request that ran out the operator's own timeout is settled too. The
	// deadline was chosen deliberately, and sending the same request three
	// more times against a host that is dropping packets only multiplies the
	// wait: a blackholed host cost over a hundred seconds for one URL.
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
}

// isPushback reports whether a status means the host wants less traffic, as
// opposed to simply having failed.
//
// Retrying and slowing down are different decisions. A 502 is worth one more
// attempt, but it says nothing about rate: it is usually the origin failing to
// reach something further back, which is exactly what an endpoint that fetches
// URLs returns when detour hands it a destination it cannot retrieve. Treating
// that as pushback collapses the per-host limiter to its floor and stalls the
// whole run against the one target that produced it.
func isPushback(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusForbidden, http.StatusServiceUnavailable:
		return true
	default:
		return false
	}
}

func sleepBackoff(ctx context.Context, attempt int) error {
	d := backoffBase * time.Duration(math.Pow(2, float64(attempt-1)))

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}

	_, _ = io.Copy(io.Discard, io.LimitReader(body, 1<<16))
	_ = body.Close()
}
