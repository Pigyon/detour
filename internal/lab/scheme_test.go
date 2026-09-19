package lab_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/nedlir/detour/internal/lab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchemeAbuseShapes(t *testing.T) {
	t.Parallel()

	srv := newLabServer(t)
	client := noFollow(t, srv)

	t.Run("OR-E01 javascript sink", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/e01?url="+url.QueryEscape("javascript:alert(1)"))
		require.Equal(t, http.StatusOK, res.Status)
		assert.Contains(t, res.Body, "javascript:alert(1)")
	})

	t.Run("OR-E02 data uri", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/e02?url="+url.QueryEscape("data:text/html,hi"))
		require.Equal(t, http.StatusOK, res.Status)
		assert.Contains(t, res.Body, "data:text/html")
	})

	t.Run("OR-E03 http downgrade", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/e03?url="+url.QueryEscape("http://"+lab.AllowedHost+"/"))
		require.Equal(t, http.StatusFound, res.Status)
		assert.Equal(t, "http://"+lab.AllowedHost+"/", res.Header.Get("Location"))
	})
}
