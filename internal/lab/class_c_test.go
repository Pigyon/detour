package lab_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/nedlir/detour/internal/lab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassCShapes(t *testing.T) {
	t.Parallel()

	srv := newLabServer(t)
	client := noFollow(t, srv)

	t.Run("OR-C01 js sink no location", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/c01?backUrl="+url.QueryEscape(attacker))
		require.Equal(t, http.StatusOK, res.Status)
		assert.Empty(t, res.Header.Get("Location"))

		body := res.Body
		assert.Contains(t, body, "location.href=")
		assert.Contains(t, body, "evil.example")
	})

	t.Run("OR-C02 hash sink", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/c02")
		require.Equal(t, http.StatusOK, res.Status)
		assert.Contains(t, res.Body, "location.hash")
	})

	t.Run("OR-C03 unsandboxed iframe", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/c03?src=/c03/frame?to="+url.QueryEscape(attacker))
		require.Equal(t, http.StatusOK, res.Status)
		body := res.Body
		assert.Contains(t, body, "<iframe")
		assert.NotContains(t, body, "sandbox=")
	})

	t.Run("OR-C04 meta refresh", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/c04?url="+url.QueryEscape(attacker))
		require.Equal(t, http.StatusOK, res.Status)
		assert.Empty(t, res.Header.Get("Location"))
		assert.Contains(t, res.Body, `http-equiv="refresh"`)
	})

	t.Run("auth backUrl requires session", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/auth/back?backUrl="+url.QueryEscape(attacker))
		require.Equal(t, http.StatusOK, res.Status)
		body := res.Body
		assert.Contains(t, body, "login required")
		assert.NotContains(t, body, "location.href")
		assert.Empty(t, res.Header.Get("Location"))
	})

	t.Run("auth backUrl with cookie", func(t *testing.T) {
		t.Parallel()

		res := doGetHeader(
			t,
			client,
			srv.URL+"/auth/back?backUrl="+url.QueryEscape(attacker),
			http.Header{"Cookie": {lab.SessionCookieName + "=" + lab.SessionCookieValue}},
		)
		require.Equal(t, http.StatusOK, res.Status)
		assert.Contains(t, res.Body, "location.href")
	})
}
