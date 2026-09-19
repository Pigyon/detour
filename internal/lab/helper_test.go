package lab_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nedlir/detour/internal/lab"
	"github.com/stretchr/testify/require"
)

type httpResult struct {
	Status int
	Header http.Header
	Body   string
}

func newLabServer(t *testing.T) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	return srv
}

func noFollow(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()

	client := srv.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return client
}

func doGet(t *testing.T, client *http.Client, rawURL string) httpResult {
	t.Helper()

	return doGetHeader(t, client, rawURL, nil)
}

func doGetHeader(t *testing.T, client *http.Client, rawURL string, headers http.Header) httpResult {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	require.NoError(t, err)

	for name, values := range headers {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}

	resp, err := client.Do(req)
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return httpResult{
		Status: resp.StatusCode,
		Header: resp.Header.Clone(),
		Body:   string(body),
	}
}

func servePath(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://lab"+target, nil)
	require.NoError(t, err)

	lab.New().Handler().ServeHTTP(rec, req)

	return rec
}
