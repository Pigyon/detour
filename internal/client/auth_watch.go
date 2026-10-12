package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// maxAuthCheckBody bounds how much of the auth-check response is read looking
// for the expect string. A login page is small; a real authenticated page
// need only show its marker near the top for this to find it.
const maxAuthCheckBody = 1 << 20

// ErrSessionExpired reports that an authenticated session was required but is
// not valid, either before the run starts or after it has begun.
var ErrSessionExpired = errors.New("client: authenticated session is not valid")

// credentials holds the cookie set the client replays. A background refresh
// can swap the whole set while requests are in flight, so reads take a
// snapshot under a read lock and writes replace the slice rather than mutate
// it in place.
type credentials struct {
	mu      sync.RWMutex
	cookies []*http.Cookie
}

func (s *credentials) snapshot() []*http.Cookie {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.cookies
}

func (s *credentials) set(cookies []*http.Cookie) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cookies = cookies
}

// reloadCookies re-reads the cookies file and swaps in the fresh set, keeping
// the inline --cookie values. A short-lived session (a five-minute bearer, a
// rotating bot-defense cookie) stays valid across a long run when the file is
// rewritten out of band, for example by re-exporting a live browser session.
func (c *Client) reloadCookies() error {
	if c.cookiesFile == "" {
		return nil
	}

	fromFile, err := parseNetscapeFile(c.cookiesFile)
	if err != nil {
		return fmt.Errorf("reloading cookies: %w", err)
	}

	refreshed := make([]*http.Cookie, 0, len(c.inline)+len(fromFile))
	refreshed = append(refreshed, c.inline...)
	refreshed = append(refreshed, fromFile...)
	c.creds.set(refreshed)

	return nil
}

// CheckAuth probes the auth-check URL with the current credentials and reports
// whether the session still looks authenticated: a 2xx response that, when an
// expect string is configured, contains it. A login redirect (any 3xx) or any
// non-2xx status counts as not authenticated. With no auth-check URL set it
// reports authenticated so callers need no special case.
func (c *Client) CheckAuth(ctx context.Context) (bool, error) {
	if c.authCheck == "" {
		return true, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.authCheck, nil)
	if err != nil {
		return false, fmt.Errorf("auth-check request: %w", err)
	}

	resp, err := c.Do(ctx, req)
	if err != nil {
		return false, fmt.Errorf("auth-check: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return false, nil
	}

	if c.authExpect == "" {
		return true, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAuthCheckBody))
	if err != nil {
		return false, fmt.Errorf("auth-check body: %w", err)
	}

	return bytes.Contains(body, []byte(c.authExpect)), nil
}

// VerifyAuth runs the auth-check once before a scan starts. With
// --auth-check-required a session that is already invalid is returned as an
// error so the run never begins unauthenticated; otherwise it only warns and
// the scan proceeds anonymously.
func (c *Client) VerifyAuth(ctx context.Context) error {
	if c.authCheck == "" {
		return nil
	}

	ok, err := c.CheckAuth(ctx)
	if err != nil {
		if c.authRequired {
			return fmt.Errorf("%w: %w", ErrSessionExpired, err)
		}

		slog.Warn("auth-check probe failed at start, continuing", "reason", err)

		return nil
	}

	if ok {
		slog.Info("auth-check ok, starting authenticated", "url", c.authCheck)

		return nil
	}

	if c.authRequired {
		return fmt.Errorf("%w: %s did not return authenticated content", ErrSessionExpired, c.authCheck)
	}

	slog.Warn("auth-check shows not authenticated at start, continuing anonymously", "url", c.authCheck)

	return nil
}

// WatchAuth keeps the session fresh and watched for the life of ctx. On each
// refresh interval it re-reads the cookies file (when one is set) and
// re-probes the auth-check URL (when one is set). A lost session calls stop
// when --auth-check-required is set, which ends the run the same as Ctrl-C;
// otherwise it warns and the run continues. It returns immediately; the work
// runs in a goroutine that exits when ctx is done. A zero refresh interval
// means no background watching.
func (c *Client) WatchAuth(ctx context.Context, stop func()) {
	if c.refresh <= 0 {
		return
	}

	go c.watchLoop(ctx, stop)
}

func (c *Client) watchLoop(ctx context.Context, stop func()) {
	ticker := time.NewTicker(c.refresh)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.reloadCookies(); err != nil {
				slog.Warn("cookie refresh failed, keeping previous session", "reason", err)
			}

			if c.probeAuthLost(ctx) && c.authRequired {
				slog.Error("authenticated session lost, stopping run", "flag", "--auth-check-required")
				stop()

				return
			}
		}
	}
}

// probeAuthLost reports whether the auth-check now shows the session is gone.
// A probe error is treated as not-lost: a transient failure should not be read
// as a logout, and a genuine logout shows as a clean not-authenticated answer.
func (c *Client) probeAuthLost(ctx context.Context) bool {
	if c.authCheck == "" {
		return false
	}

	ok, err := c.CheckAuth(ctx)
	if err != nil {
		slog.Warn("auth-check probe failed, keeping session", "reason", err)

		return false
	}

	if ok {
		slog.Debug("auth-check ok, session still authenticated")

		return false
	}

	if !c.authRequired {
		slog.Warn("authenticated session lost, continuing unauthenticated; findings may be incomplete")
	}

	return true
}
