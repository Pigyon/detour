package lab_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInfrastructureShapes(t *testing.T) {
	t.Parallel()

	srv := newLabServer(t)
	client := noFollow(t, srv)

	t.Run("OR-D01 x-forwarded-host", func(t *testing.T) {
		t.Parallel()

		res := doGetHeader(t, client, srv.URL+"/d01/path", http.Header{
			"X-Forwarded-Host": {"evil.example"},
		})
		require.Equal(t, http.StatusFound, res.Status)
		assert.Contains(t, res.Header.Get("Location"), "https://evil.example/")
	})

	t.Run("OR-D02 destHost", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/_next/d02?destHost=evil.example")
		require.Equal(t, http.StatusFound, res.Status)
		assert.Equal(t, "https://evil.example/", res.Header.Get("Location"))
		assert.Equal(t, "MISS", res.Header.Get("X-Nextjs-Cache"))
	})

	t.Run("OR-D03 raw path location", func(t *testing.T) {
		t.Parallel()

		rec := servePath(t, "/d03//evil.example/")
		require.Equal(t, http.StatusMovedPermanently, rec.Code)
		assert.Equal(t, "//evil.example/", rec.Header().Get("Location"))
	})

	t.Run("OR-D04 relaystate", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/saml/acs?RelayState="+url.QueryEscape(attacker))
		require.Equal(t, http.StatusFound, res.Status)
		assert.Equal(t, attacker, res.Header.Get("Location"))
	})

	t.Run("OR-D04 ws-federation wreply", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/adfs/ls?wreply="+url.QueryEscape(attacker))
		require.Equal(t, http.StatusFound, res.Status)
		assert.Equal(t, attacker, res.Header.Get("Location"))
	})

	t.Run("OR-D05 referer", func(t *testing.T) {
		t.Parallel()

		res := doGetHeader(t, client, srv.URL+"/d05", http.Header{
			"Referer": {attacker},
		})
		require.Equal(t, http.StatusFound, res.Status)
		assert.Equal(t, attacker, res.Header.Get("Location"))
	})

	t.Run("OR-D06 refresh header", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/d06?url="+url.QueryEscape(attacker))
		require.Equal(t, http.StatusOK, res.Status)
		assert.Empty(t, res.Header.Get("Location"))
		assert.Equal(t, "0;url="+attacker, res.Header.Get("Refresh"))
	})
}
