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
)

// Client issues scoped, credential-safe HTTP requests and never follows redirects.
type Client struct {
	transport http.RoundTripper
	guard     *scope.Guard
	extra     http.Header
	cookies   []*http.Cookie
	rate      rate.Limit
	delay     time.Duration
	timeout   time.Duration
	limiters  sync.Map
}

// New builds a client from cfg. Credentials are attached only after the guard
// allows the host.
func New(cfg config.Config, guard *scope.Guard) (*Client, error) {
	if guard == nil {
		return nil, errors.New("nil scope guard")
	}

	headers, err := config.ParseHeaders(cfg.Headers)
	if err != nil {
		return nil, err
	}

	cookies, err := loadCookies(cfg)
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

	return &Client{
		transport: transport,
		timeout:   cfg.Timeout,
		guard:     guard,
		extra:     headers,
		cookies:   cookies,
		rate:      limit,
		delay:     cfg.Delay,
	}, nil
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

	applyCredentials(req, c.extra, c.cookies)

	if err := c.wait(ctx, host); err != nil {
		return nil, err
	}

	return c.doWithRetry(ctx, req)
}

func (c *Client) wait(ctx context.Context, host string) error {
	limiter := c.limiterFor(host)
	if err := limiter.Wait(ctx); err != nil {
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

func (c *Client) limiterFor(host string) *rate.Limiter {
	if got, ok := c.limiters.Load(host); ok {
		limiter, ok := got.(*rate.Limiter)
		if ok {
			return limiter
		}
	}

	created := rate.NewLimiter(c.rate, defaultBurst)
	actual, _ := c.limiters.LoadOrStore(host, created)

	limiter, ok := actual.(*rate.Limiter)
	if !ok {
		return created
	}

	return limiter
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
		if isPushback(resp.StatusCode) && !slowed {
			slowed = true

			c.slowHost(req.URL.Hostname())
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
	limiter := c.limiterFor(host)

	next := limiter.Limit() / 2
	if next < minRate {
		next = minRate
	}

	limiter.SetLimit(next)
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
