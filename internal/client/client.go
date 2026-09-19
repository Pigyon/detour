// Package client is the shared HTTP client with scope, auth, and rate limits.
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/nedlir/detour/internal/config"
	"github.com/nedlir/detour/internal/scope"
	"golang.org/x/time/rate"
)

const (
	maxRetries     = 3
	minRate        = 0.1
	backoffBase    = 200 * time.Millisecond
	defaultBurst   = 1
	retryStatusMin = 429
)

// Client issues scoped, credential-safe HTTP requests and never follows redirects.
type Client struct {
	http       *http.Client
	guard      *scope.Guard
	extra      http.Header
	cookies    []*http.Cookie
	rate       rate.Limit
	delay      time.Duration
	limiters   sync.Map
	maxRetries int
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
		http: &http.Client{
			Transport:     transport,
			Timeout:       cfg.Timeout,
			CheckRedirect: denyRedirect,
		},
		guard:      guard,
		extra:      headers,
		cookies:    cookies,
		rate:       limit,
		delay:      cfg.Delay,
		maxRetries: maxRetries,
	}, nil
}

func denyRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
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
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			if err := sleepBackoff(ctx, attempt); err != nil {
				return nil, err
			}
		}

		cloned := req.Clone(ctx)

		resp, err := c.http.Do(cloned)
		if err != nil {
			lastErr = err

			if ctx.Err() != nil {
				return nil, ctx.Err()
			}

			continue
		}

		if !shouldRetry(resp.StatusCode) {
			return resp, nil
		}

		c.slowHost(req.URL.Hostname())

		lastErr = fmt.Errorf("status %d", resp.StatusCode)
		drainAndClose(resp.Body)
	}

	return nil, fmt.Errorf("request failed: %w", lastErr)
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
	case http.StatusTooManyRequests, http.StatusForbidden, http.StatusBadGateway, http.StatusServiceUnavailable:
		return true
	default:
		return status >= retryStatusMin && status < 500
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
