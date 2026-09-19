package lab_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/nedlir/detour/internal/lab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClickRoundTrip(t *testing.T) {
	t.Parallel()

	blob, err := lab.EncodeClick(attacker)
	require.NoError(t, err)

	env, err := lab.DecodeClick(blob + ".html")
	require.NoError(t, err)
	assert.Equal(t, attacker, env.Dest)
	assert.Equal(t, 106519, env.Campaign)
}

func TestClickIgnoresIntegrity(t *testing.T) {
	t.Parallel()

	blob, err := lab.EncodeClick(attacker)
	require.NoError(t, err)

	env, err := lab.DecodeClick(blob)
	require.NoError(t, err)
	assert.NotEmpty(t, env.Integrity)
}

func FuzzDecodeClick(f *testing.F) {
	seed, err := lab.EncodeClick("https://example.com/")
	if err != nil {
		f.Fatal(err)
	}

	f.Add(seed)
	f.Add(seed + ".html")
	f.Add("")
	f.Add("!!!!")
	f.Add("eJxt")

	f.Fuzz(func(_ *testing.T, blob string) {
		_, _ = lab.DecodeClick(blob)
	})
}

func TestClassBShapes(t *testing.T) {
	t.Parallel()

	srv := newLabServer(t)
	client := noFollow(t, srv)

	blob, err := lab.EncodeClick(attacker)
	require.NoError(t, err)

	upnJSON, err := json.Marshal(map[string]string{"url": attacker})
	require.NoError(t, err)

	upn := base64.URLEncoding.EncodeToString(upnJSON)
	token := unsignedJWT(t, attacker)

	t.Run("OR-B01 click wrapper", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/track/click2/"+blob+".html")
		require.Equal(t, http.StatusFound, res.Status)
		assert.Equal(t, attacker, res.Header.Get("Location"))
	})

	t.Run("OR-B02 upn wrapper", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/ls/click?upn="+url.QueryEscape(upn))
		require.Equal(t, http.StatusFound, res.Status)
		assert.Equal(t, attacker, res.Header.Get("Location"))
	})

	t.Run("OR-B03 jwt", func(t *testing.T) {
		t.Parallel()

		res := doGet(t, client, srv.URL+"/b03?token="+url.QueryEscape(token))
		require.Equal(t, http.StatusFound, res.Status)
		assert.Equal(t, attacker, res.Header.Get("Location"))
	})

	t.Run("OR-B04 double decode", func(t *testing.T) {
		t.Parallel()

		raw := url.QueryEscape(url.QueryEscape(attacker))
		res := doGet(t, client, srv.URL+"/b04?next="+raw)
		require.Equal(t, http.StatusFound, res.Status)
		assert.Equal(t, attacker, res.Header.Get("Location"))
	})

	t.Run("OR-B05 chain", func(t *testing.T) {
		t.Parallel()

		inner := srv.URL + "/b05/inner?url=" + url.QueryEscape(attacker)
		res := doGet(t, client, srv.URL+"/b05?url="+url.QueryEscape(inner))
		require.Equal(t, http.StatusFound, res.Status)
		assert.Equal(t, inner, res.Header.Get("Location"))

		res2 := doGet(t, client, inner)
		require.Equal(t, http.StatusFound, res2.Status)
		assert.Equal(t, attacker, res2.Header.Get("Location"))
	})
}

func unsignedJWT(t *testing.T, dest string) string {
	t.Helper()

	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload, err := json.Marshal(map[string]string{"redirect": dest})
	require.NoError(t, err)

	return hdr + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}
