package hidden_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/nedlir/detour/internal/hidden"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// directDoer mirrors the real scoped client in the one way that matters
// here: it never follows a redirect, so the Location header survives to be
// read.
type directDoer struct{ hits atomic.Int64 }

func (d *directDoer) Do(_ context.Context, req *http.Request) (*http.Response, error) {
	d.hits.Add(1)

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return client.Do(req)
}

// TestDiscoverPromotesOnlyReactingParameters is the whole point: a name is
// promoted when the server does something with it, never because it was
// guessed.
func TestDiscoverPromotesOnlyReactingParameters(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Query().Get("backUrl") != "":
			w.Header().Set("Location", r.URL.Query().Get("backUrl"))
			w.WriteHeader(http.StatusFound)
		case r.URL.Query().Get("ref") != "":
			//nolint:gosec // G705: reflecting the probe is what this fixture tests.
			_, _ = fmt.Fprintf(w, "<p>came from %s</p>", r.URL.Query().Get("ref"))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)

	f := hidden.New(&directDoer{}, hidden.Options{})

	hits, err := f.Discover(context.Background(), srv.URL+"/page")
	require.NoError(t, err)

	byParam := map[string]hidden.Evidence{}
	for _, h := range hits {
		byParam[h.Param] = h.Evidence
	}

	assert.Equal(t, hidden.EvidenceRedirect, byParam["backUrl"], "a Location is the strong signal")
	assert.Equal(t, hidden.EvidenceReflected, byParam["ref"], "a body reflection is the weak one")
	assert.Len(t, hits, 2, "nothing else is promoted")
}

func TestDiscoverIgnoresParametersAlreadyPresent(t *testing.T) {
	t.Parallel()

	var probed atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("url") {
			probed.Add(1)
		}

		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	f := hidden.New(&directDoer{}, hidden.Options{Names: []string{"url"}})

	hits, err := f.Discover(context.Background(), srv.URL+"/page?url=already")
	require.NoError(t, err)
	assert.Empty(t, hits)
	assert.Zero(t, probed.Load(), "a parameter the endpoint already carries is not hidden")
}

func TestDiscoverSilentEndpointYieldsNothing(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	hits, err := hidden.New(&directDoer{}, hidden.Options{}).Discover(context.Background(), srv.URL+"/page")
	require.NoError(t, err)
	assert.Empty(t, hits)
}

func TestPromote(t *testing.T) {
	t.Parallel()

	got := hidden.Promote([]hidden.Hit{
		{Probe: "https://a.lab/p?url=x"},
		{Probe: "https://a.lab/p?next=x"},
	})

	assert.Equal(t, []string{"https://a.lab/p?url=x", "https://a.lab/p?next=x"}, got)
}
