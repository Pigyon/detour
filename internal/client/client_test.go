package client_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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
