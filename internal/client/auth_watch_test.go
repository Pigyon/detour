package client_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nedlir/detour/internal/client"
	"github.com/nedlir/detour/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authMarker is the authenticated-only string authServer writes once it sees
// the session cookie.
const authMarker = "welcome"

// authServer answers /me with authenticated content when it sees the session
// cookie, and sends a login redirect otherwise. It is the shape of a real
// authenticated-only endpoint: a logged-out request never reaches the page.
func authServer(t *testing.T) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sess"); err == nil && c.Value == "good" {
			_, _ = io.WriteString(w, authMarker+" rsps758x2490")

			return
		}

		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	return srv
}

func TestCheckAuthReportsAuthenticated(t *testing.T) {
	t.Parallel()

	srv := authServer(t)
	cfg := config.Config{
		Cookie:          "sess=good",
		AuthCheck:       srv.URL + "/me",
		AuthCheckExpect: authMarker,
	}
	c := newTestClient(t, cfg, hostOf(t, srv.URL))

	ok, err := c.CheckAuth(context.Background())
	require.NoError(t, err)
	assert.True(t, ok, "a 2xx response carrying the expect string is authenticated")
}

func TestCheckAuthDetectsLoginRedirect(t *testing.T) {
	t.Parallel()

	srv := authServer(t)
	cfg := config.Config{
		AuthCheck:       srv.URL + "/me",
		AuthCheckExpect: authMarker,
	}
	c := newTestClient(t, cfg, hostOf(t, srv.URL))

	ok, err := c.CheckAuth(context.Background())
	require.NoError(t, err)
	assert.False(t, ok, "a login redirect means the session is not authenticated")
}

func TestCheckAuthExpectMissingIsNotAuthenticated(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "this is the public page")
	}))
	t.Cleanup(srv.Close)

	cfg := config.Config{AuthCheck: srv.URL + "/me", AuthCheckExpect: authMarker}
	c := newTestClient(t, cfg, hostOf(t, srv.URL))

	ok, err := c.CheckAuth(context.Background())
	require.NoError(t, err)
	assert.False(t, ok, "a 2xx without the expect string is not proof of a session")
}

func TestCheckAuthNoURLIsAuthenticated(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, config.Config{}, "example.test")

	ok, err := c.CheckAuth(context.Background())
	require.NoError(t, err)
	assert.True(t, ok, "with no auth-check configured the client reports authenticated")
}

func TestVerifyAuthRequiredFailsFast(t *testing.T) {
	t.Parallel()

	srv := authServer(t)
	cfg := config.Config{
		AuthCheck:         srv.URL + "/me",
		AuthCheckExpect:   "welcome",
		AuthCheckRequired: true,
	}
	c := newTestClient(t, cfg, hostOf(t, srv.URL))

	err := c.VerifyAuth(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, client.ErrSessionExpired,
		"a required session that is not valid must stop the run before it starts")
}

func TestVerifyAuthNotRequiredContinues(t *testing.T) {
	t.Parallel()

	srv := authServer(t)
	cfg := config.Config{
		AuthCheck:       srv.URL + "/me",
		AuthCheckExpect: authMarker,
	}
	c := newTestClient(t, cfg, hostOf(t, srv.URL))

	assert.NoError(t, c.VerifyAuth(context.Background()),
		"without --auth-check-required a lost session only warns and the scan proceeds")
}

func TestReloadCookiesRefreshesFileKeepingInline(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "jar.txt")
	writeJar(t, path, "sessold")

	cfg := config.Config{Cookie: "inline=1", CookiesFile: path}
	c := newTestClient(t, cfg, "example.test")

	assert.ElementsMatch(t, []string{"inline", "sessold"}, c.LiveCookieNames(),
		"the live set starts as the inline cookie plus the file")

	writeJar(t, path, "sessnew")
	require.NoError(t, c.ReloadCookies())

	assert.ElementsMatch(t, []string{"inline", "sessnew"}, c.LiveCookieNames(),
		"a reload swaps the file-backed cookie and keeps the inline one")
}

// writeJar writes a one-cookie Netscape jar whose cookie is named after name,
// so a test can rewrite the file and see the live set change.
func writeJar(t *testing.T, path, name string) {
	t.Helper()

	line := strings.Join([]string{"example.test", "FALSE", "/", "FALSE", "0", name, "v"}, "\t")
	require.NoError(t, os.WriteFile(path, []byte(line+"\n"), 0o600))
}

// TestWatchAuthStopsRunWhenRequiredSessionLost proves the background watcher
// ends the run, the same as Ctrl-C, once a required session is gone.
func TestWatchAuthStopsRunWhenRequiredSessionLost(t *testing.T) {
	t.Parallel()

	srv := authServer(t) // no session cookie set, so /me always redirects.
	cfg := config.Config{
		AuthCheck:         srv.URL + "/me",
		AuthCheckExpect:   "welcome",
		AuthCheckRequired: true,
		CookiesRefresh:    10 * time.Millisecond,
	}
	c := newTestClient(t, cfg, hostOf(t, srv.URL))

	stopped := make(chan struct{})

	c.WatchAuth(t.Context(), func() { close(stopped) })

	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher never stopped the run on a lost required session")
	}
}
