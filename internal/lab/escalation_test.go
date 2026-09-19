package lab_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/nedlir/detour/internal/lab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEscalationScenarios(t *testing.T) {
	t.Parallel()

	srv := newLabServer(t)
	client := noFollow(t, srv)

	t.Run("OR-F01 nested redirect_uri", func(t *testing.T) {
		t.Parallel()

		nested := "https://" + lab.AllowedHost + "/callback/../a01?url=" + attacker
		res := doGet(t, client, srv.URL+"/oauth/authorize?redirect_uri="+url.QueryEscape(nested))
		require.Equal(t, http.StatusFound, res.Status)
		assert.Equal(t, nested, res.Header.Get("Location"))
	})

	t.Run("OR-F02 csp redir", func(t *testing.T) {
		t.Parallel()

		page := doGet(t, client, srv.URL+"/csp")
		require.Equal(t, http.StatusOK, page.Status)
		assert.Contains(t, page.Header.Get("Content-Security-Policy"), lab.AllowedHost)

		res := doGet(t, client, srv.URL+"/csp/redir?url="+url.QueryEscape(attacker))
		require.Equal(t, http.StatusFound, res.Status)
		assert.Equal(t, attacker, res.Header.Get("Location"))
	})

	t.Run("OR-F03 ssrf stays in lab", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/ssrf/fetch?url="+url.QueryEscape(srv.URL+"/landed"))
		require.Equal(t, http.StatusOK, res.Status)
		assert.Contains(t, res.Body, "landed")
	})

	t.Run("OR-F03 never fetches off-lab", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/ssrf/fetch?url="+url.QueryEscape("http://169.254.169.254/"))
		require.Equal(t, http.StatusBadRequest, res.Status)
		assert.Contains(t, res.Body, "blocked-off-lab")
	})

	t.Run("OR-F04 token plus next", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/f04/reset?token=lab-reset-token&next="+url.QueryEscape(attacker))
		require.Equal(t, http.StatusFound, res.Status)
		assert.Equal(t, attacker, res.Header.Get("Location"))
	})

	t.Run("OR-F05 phishing redirect", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/f05?url="+url.QueryEscape(srv.URL+"/login-page"))
		require.Equal(t, http.StatusFound, res.Status)
		assert.Contains(t, res.Header.Get("Location"), "/login-page")
	})
}

func TestEscalationPrimitives(t *testing.T) {
	t.Parallel()

	srv := newLabServer(t)
	client := noFollow(t, srv)

	t.Run("OR-F06 same host only", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/f06?url="+url.QueryEscape(attacker))
		require.Equal(t, http.StatusBadRequest, res.Status)

		res2 := doGet(t, client, srv.URL+"/f06?url="+url.QueryEscape("/landed"))
		require.Equal(t, http.StatusFound, res2.Status)
		assert.Equal(t, "/landed", res2.Header.Get("Location"))
	})

	t.Run("OR-F07 hop chain", func(t *testing.T) {
		t.Parallel()

		r1 := doGet(t, client, srv.URL+"/f07/r1")
		require.Equal(t, http.StatusFound, r1.Status)
		assert.Equal(t, "/f07/r2", r1.Header.Get("Location"))

		r2 := doGet(t, client, srv.URL+"/f07/r2")
		require.Equal(t, http.StatusFound, r2.Status)
		assert.Equal(t, "/landed", r2.Header.Get("Location"))
	})

	t.Run("OR-F08 scheme change location", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/f08?url="+url.QueryEscape("gopher://127.0.0.1:6379/_info"))
		require.Equal(t, http.StatusFound, res.Status)
		assert.Equal(t, "gopher://127.0.0.1:6379/_info", res.Header.Get("Location"))
	})

	t.Run("OR-F09 missing noopener", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/f09")
		require.Equal(t, http.StatusOK, res.Status)
		body := res.Body
		assert.Contains(t, body, `target="_blank"`)
		assert.NotContains(t, body, "noopener")
	})

	t.Run("OR-F10 cache poison on cb key", func(t *testing.T) {
		t.Parallel()

		poisoned := doGetHeader(t, client, srv.URL+"/f10?cb=unique-test-key", http.Header{
			"X-Forwarded-Host": {"evil.example"},
		})
		require.Equal(t, http.StatusFound, poisoned.Status)
		assert.Equal(t, "MISS", poisoned.Header.Get("X-Cache"))

		hit := doGet(t, client, srv.URL+"/f10?cb=unique-test-key")
		require.Equal(t, http.StatusFound, hit.Status)
		assert.Equal(t, "HIT", hit.Header.Get("X-Cache"))
		assert.Contains(t, hit.Header.Get("Location"), "evil.example")
	})

	t.Run("landed sink", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/landed")
		require.Equal(t, http.StatusOK, res.Status)
		assert.Equal(t, "landed\n", res.Body)
	})
}

func TestDecoys(t *testing.T) {
	t.Parallel()

	srv := newLabServer(t)
	client := noFollow(t, srv)

	t.Run("exact allowlist rejects attacker", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/decoy/allowlist?backUrl="+url.QueryEscape(attacker))
		require.Equal(t, http.StatusBadRequest, res.Status)
	})

	t.Run("exact allowlist rejects userinfo", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/decoy/allowlist?backUrl="+url.QueryEscape("https://"+lab.AllowedHost+"@evil.example/"))
		require.Equal(t, http.StatusBadRequest, res.Status)
	})

	t.Run("exact allowlist allows https allowed host", func(t *testing.T) {
		t.Parallel()

		dest := "https://" + lab.AllowedHost + "/home"
		res := doGet(t, client, srv.URL+"/decoy/allowlist?backUrl="+url.QueryEscape(dest))
		require.Equal(t, http.StatusFound, res.Status)
		assert.Equal(t, dest, res.Header.Get("Location"))
	})

	t.Run("static redirect", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/decoy/static")
		require.Equal(t, http.StatusFound, res.Status)
		assert.Equal(t, "https://"+lab.AllowedHost+"/home", res.Header.Get("Location"))
	})

	t.Run("reflect has no location", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/decoy/reflect?url="+url.QueryEscape(attacker))
		require.Equal(t, http.StatusOK, res.Status)
		assert.Empty(t, res.Header.Get("Location"))
		assert.Contains(t, res.Body, "evil.example")
	})

	t.Run("signed blob verifies", func(t *testing.T) {
		t.Parallel()

		blob := lab.SignDest("https://" + lab.AllowedHost + "/ok")
		res := doGet(t, client, srv.URL+"/decoy/signed/"+blob)
		require.Equal(t, http.StatusFound, res.Status)
		assert.Equal(t, "https://"+lab.AllowedHost+"/ok", res.Header.Get("Location"))
	})

	t.Run("signed blob rejects tamper", func(t *testing.T) {
		t.Parallel()

		blob := lab.SignDest(attacker)
		res := doGet(t, client, srv.URL+"/decoy/signed/"+blob+"tamper")
		require.Equal(t, http.StatusBadRequest, res.Status)
	})
}
