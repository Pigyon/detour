package harvest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nedlir/detour/internal/harvest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// directDoer issues requests with no scope guard, for tests that point at a
// local fixture.
type directDoer struct {
	hits atomic.Int64
}

func (d *directDoer) Do(_ context.Context, req *http.Request) (*http.Response, error) {
	d.hits.Add(1)

	return http.DefaultClient.Do(req)
}

// recordedProvider replays a fixture, so provider wiring is testable without
// contacting an archive.
type recordedProvider struct {
	name  string
	urls  []string
	err   error
	calls atomic.Int64
}

func (r *recordedProvider) Name() string        { return r.name }
func (r *recordedProvider) Rate() time.Duration { return 0 }

func (r *recordedProvider) Fetch(context.Context, string) ([]string, error) {
	r.calls.Add(1)

	return r.urls, r.err
}

// urlOne is the archive fixture URL used across the provider cases.
const (
	urlOne        = "https://a.lab/one"
	sourceWayback = "wayback"
)

func TestHarvestCollectsFromEveryProvider(t *testing.T) {
	t.Parallel()

	a := &recordedProvider{name: sourceWayback, urls: []string{urlOne}}
	b := &recordedProvider{name: "otx", urls: []string{"https://a.lab/two"}}

	h := harvest.New(&directDoer{}, harvest.Options{
		Passive:   true,
		Providers: []harvest.Provider{a, b},
	})

	result := h.Run(context.Background(), "a.lab", "")

	assert.ElementsMatch(t, []string{urlOne, "https://a.lab/two"}, result.URLs)
	assert.ElementsMatch(t, []string{sourceWayback, "otx"}, result.Sources)
	assert.Empty(t, result.Errors)
	assert.Equal(t, int64(1), a.calls.Load())
	assert.Equal(t, int64(1), b.calls.Load())
}

// TestHarvestKeepsProviderFailures is the honesty rule: a source that failed
// is named, not silently dropped.
func TestHarvestKeepsProviderFailures(t *testing.T) {
	t.Parallel()

	good := &recordedProvider{name: sourceWayback, urls: []string{urlOne}}
	bad := &recordedProvider{name: "commoncrawl", err: assert.AnError}

	h := harvest.New(&directDoer{}, harvest.Options{
		Passive:   true,
		Providers: []harvest.Provider{good, bad},
	})

	result := h.Run(context.Background(), "a.lab", "")

	assert.Equal(t, []string{urlOne}, result.URLs)
	assert.Equal(t, []string{sourceWayback}, result.Sources)
	require.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0], "commoncrawl")
}

// TestPassiveIssuesZeroTargetRequests is the contract of --passive: archives
// only, not one packet to the host under test.
func TestPassiveIssuesZeroTargetRequests(t *testing.T) {
	t.Parallel()

	var hits atomic.Int64

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)

	provider := &recordedProvider{name: sourceWayback, urls: []string{urlOne}}

	h := harvest.New(&directDoer{}, harvest.Options{
		Passive:   true,
		Providers: []harvest.Provider{provider},
		Crawler:   &countingCrawler{},
	})

	result := h.Run(context.Background(), "a.lab", target.URL)

	assert.Zero(t, hits.Load(), "passive must never touch the target")
	assert.NotEmpty(t, result.URLs, "archives still produce results")
}

type countingCrawler struct{ calls atomic.Int64 }

func (c *countingCrawler) Crawl(context.Context, string) ([]string, error) {
	c.calls.Add(1)

	return []string{"https://a.lab/crawled"}, nil
}

func TestActiveRunUsesFreebiesAndCrawl(t *testing.T) {
	t.Parallel()

	srv := freebieServer(t)
	crawler := &countingCrawler{}

	h := harvest.New(&directDoer{}, harvest.Options{
		Providers: []harvest.Provider{&recordedProvider{name: sourceWayback}},
		Crawler:   crawler,
	})

	result := h.Run(context.Background(), "a.lab", srv.URL)

	assert.Equal(t, int64(1), crawler.calls.Load())
	assert.Contains(t, result.Sources, "crawl")
	assert.Contains(t, result.Sources, "freebies")
	assert.Contains(t, result.URLs, "https://a.lab/crawled")
}

// freebieServer publishes the files a real site publishes about itself.
func freebieServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin/panel\nAllow: /go\nSitemap: %SELF%/sitemap.xml\n"))
	})

	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<?xml version="1.0"?><sitemapindex><sitemap><loc>%SELF%/sitemap-1.xml</loc></sitemap></sitemapindex>`))
	})

	mux.HandleFunc("/sitemap-1.xml", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<?xml version="1.0"?><urlset><url><loc>%SELF%/deep/page?next=/x</loc></url></urlset>`))
	})

	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{
			"paths": map[string]any{"/v1/redirect": map[string]any{}, "/v1/users": map[string]any{}},
		}
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)

		body := strings.ReplaceAll(rec.Body.String(), "%SELF%", "http://"+r.Host)
		w.WriteHeader(rec.Code)
		_, _ = w.Write([]byte(body)) //nolint:gosec // G705: fixture content this test authored.
	}))
	t.Cleanup(srv.Close)

	return srv
}

func TestFreebies(t *testing.T) {
	t.Parallel()

	srv := freebieServer(t)

	urls, _ := harvest.Freebies(context.Background(), &directDoer{}, srv.URL)

	joined := strings.Join(urls, "\n")
	assert.Contains(t, joined, "/admin/panel", "robots disallow entries are endpoints too")
	assert.Contains(t, joined, "/go")
	assert.Contains(t, joined, "/v1/redirect", "openapi paths are read")
	assert.Contains(t, joined, "/deep/page", "the sitemap index is followed")
}

func TestSitemapRecursionIsBounded(t *testing.T) {
	t.Parallel()

	var served atomic.Int64

	// A sitemap index that points at itself forever.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		//nolint:gosec // G705: fixture content this test authored.
		_, _ = w.Write([]byte(`<?xml version="1.0"?><sitemapindex><sitemap><loc>http://` +
			r.Host + `/sitemap-` + r.URL.Path + `.xml</loc></sitemap></sitemapindex>`))
	}))
	t.Cleanup(srv.Close)

	root, err := url.Parse(srv.URL)
	require.NoError(t, err)

	_, _ = harvest.Sitemaps(context.Background(), &directDoer{}, root)

	assert.Less(t, served.Load(), int64(60), "a self-referential sitemap must terminate")
}

func TestSourceMaps(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		script string
		want   string
	}{
		{name: "hash form", script: "var a=1;\n//# sourceMappingURL=app.js.map", want: "https://a.lab/static/app.js.map"},
		{name: "at form", script: "var a=1;\n//@ sourceMappingURL=app.js.map", want: "https://a.lab/static/app.js.map"},
		{name: "absolute", script: "//# sourceMappingURL=https://cdn.a.lab/x.map", want: "https://cdn.a.lab/x.map"},
		{name: "data uri skipped", script: "//# sourceMappingURL=data:application/json;base64,e30=", want: ""},
		{name: "absent", script: "var a=1;", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := harvest.SourceMaps("https://a.lab/static/app.js", []byte(tt.script))

			if tt.want == "" {
				assert.Empty(t, got)

				return
			}

			require.Len(t, got, 1)
			assert.Equal(t, tt.want, got[0])
		})
	}
}

// TestWebCrawlerFollowsLinksAndScripts covers the crawl stage detour writes
// itself: links from markup, endpoints from a bundle.
func TestWebCrawlerFollowsLinksAndScripts(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<a href="/go?next=/home">go</a><script src="/app.js"></script>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`fetch("/api/v1/redirect?url=x"); var u = "/api/v1/users";`))
	})
	mux.HandleFunc("/go", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<p>go</p>`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := harvest.NewCrawler(&directDoer{}, harvest.CrawlOptions{
		Depth: 2, JSCrawl: true, SameHost: true,
	})

	urls, err := c.Crawl(context.Background(), srv.URL+"/")
	require.NoError(t, err)

	joined := strings.Join(urls, "\n")
	assert.Contains(t, joined, "/go?next=/home", "markup links are followed")
	assert.Contains(t, joined, "/app.js", "script sources are collected")
	assert.Contains(t, joined, "/api/v1/redirect", "endpoints inside a bundle are found")
}

// TestWebCrawlerRespectsBudget stops a crawl on a site with infinite URLs.
func TestWebCrawlerRespectsBudget(t *testing.T) {
	t.Parallel()

	var served atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		//nolint:gosec // G705: fixture content this test authored.
		_, _ = w.Write([]byte(`<a href="` + r.URL.Path + `a">deeper</a><a href="` + r.URL.Path + `b">deeper</a>`))
	}))
	t.Cleanup(srv.Close)

	c := harvest.NewCrawler(&directDoer{}, harvest.CrawlOptions{
		Depth: 20, MaxPages: 10, SameHost: true,
	})

	_, err := c.Crawl(context.Background(), srv.URL+"/")
	require.NoError(t, err)
	assert.LessOrEqual(t, served.Load(), int64(11), "the page budget bounds the crawl")
}

// TestWebCrawlerStaysOnHost keeps the crawler from wandering.
//
// localhost and 127.0.0.1 are the same address but different hostnames, which
// is what lets one test server stand in for an off-host link.
func TestWebCrawlerStaysOnHost(t *testing.T) {
	t.Parallel()

	var offsite atomic.Int64

	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		offsite.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(other.Close)

	otherURL, err := url.Parse(other.URL)
	require.NoError(t, err)

	offHost := "http://localhost:" + otherURL.Port() + "/x"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<a href="` + offHost + `">offsite</a>`))
	}))
	t.Cleanup(srv.Close)

	c := harvest.NewCrawler(&directDoer{}, harvest.CrawlOptions{Depth: 2, SameHost: true})

	urls, err := c.Crawl(context.Background(), srv.URL+"/")
	require.NoError(t, err)
	assert.Empty(t, urls, "an off-host link is not followed")
	assert.Zero(t, offsite.Load())
}
