package js_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nedlir/detour/internal/js"
	"github.com/nedlir/detour/internal/lab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mapFetcher serves a fixed set of URLs, so page collection is testable with
// no server at all.
type mapFetcher map[string]string

func (m mapFetcher) Get(_ context.Context, rawURL string) ([]byte, error) {
	body, ok := m[rawURL]
	if !ok {
		return nil, errors.New("not found: " + rawURL)
	}

	return []byte(body), nil
}

func TestCollectPageFollowsScripts(t *testing.T) {
	t.Parallel()

	f := mapFetcher{
		pageURL:                     `<script src="/a.js"></script><script>location.href=location.hash.slice(1)</script>`,
		"https://site.lab/a.js":     `function g(u){ location.assign(u) }`,
		"https://site.lab/a.js.map": ``,
	}

	page, err := js.CollectPage(context.Background(), f, pageURL)
	require.NoError(t, err)
	require.Len(t, page.Scripts, 2)
	assert.Equal(t, "https://site.lab/a.js", page.Scripts[0].Source)
	assert.Contains(t, page.Scripts[1].Source, "(inline)")

	_, hasHash := verdictByID(page.Verdicts, "OR-C02")
	assert.True(t, hasHash, "the inline hash sink is reported")
}

// TestCollectPagePrefersSourceMap proves the original sources win over the
// bundle: a minified guard name is useless in a report.
func TestCollectPagePrefersSourceMap(t *testing.T) {
	t.Parallel()

	sm, err := json.Marshal(map[string]any{
		"sources": []string{"src/nav.js"},
		"sourcesContent": []string{`function checkDestination(u){ return u.startsWith("https://a.lab") }
function go(u){ if (checkDestination(u)) location.href = u }`},
	})
	require.NoError(t, err)

	f := mapFetcher{
		pageURL:                     `<script src="/b.js"></script>`,
		"https://site.lab/b.js":     `function n(u){if(t(u))location.href=u}`,
		"https://site.lab/b.js.map": string(sm),
	}

	page, err := js.CollectPage(context.Background(), f, pageURL)
	require.NoError(t, err)
	require.Len(t, page.Scripts, 1)
	assert.Equal(t, "src/nav.js", page.Scripts[0].Source)
	require.Len(t, page.Scripts[0].Sinks, 1)
	require.NotNil(t, page.Scripts[0].Sinks[0].Validator)
	assert.Equal(t, "checkDestination", page.Scripts[0].Sinks[0].Validator.Name)
}

func TestCollectPageRecordsFetchErrors(t *testing.T) {
	t.Parallel()

	f := mapFetcher{pageURL: `<script src="/missing.js"></script>`}

	page, err := js.CollectPage(context.Background(), f, pageURL)
	require.NoError(t, err)
	assert.Empty(t, page.Scripts)
	require.NotEmpty(t, page.Errors, "a report never looks complete when a script could not be read")
	assert.Contains(t, page.Errors[0], "missing.js")
}

func TestCollectPageBareScript(t *testing.T) {
	t.Parallel()

	f := mapFetcher{"https://site.lab/app.js": `location.href = location.hash.slice(1)`}

	page, err := js.CollectPage(context.Background(), f, "https://site.lab/app.js")
	require.NoError(t, err)
	require.Len(t, page.Scripts, 1)

	_, ok := verdictByID(page.Verdicts, "OR-C02")
	assert.True(t, ok)
}

// TestCollectPageAgainstLab is the recall gate for the JS stage: the loose
// bundle is read through its page, and the correctly guarded decoy stays
// silent.
func TestCollectPageAgainstLab(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	f := liveFetcher{}

	page, err := js.CollectPage(context.Background(), f, srv.URL+"/app/signin")
	require.NoError(t, err)
	assert.Empty(t, page.Errors)

	for _, want := range []string{"OR-A13", "OR-A01", "OR-E01"} {
		_, ok := verdictByID(page.Verdicts, want)
		assert.True(t, ok, "missing %s in %v", want, ids(page.Verdicts))
	}

	require.Len(t, page.Scripts, 1)
	require.Len(t, page.Scripts[0].Sinks, 1)
	assert.Equal(t, "backUrl", page.Scripts[0].Sinks[0].Origin.Param)

	decoy, err := js.CollectPage(context.Background(), f, srv.URL+"/decoy/guarded")
	require.NoError(t, err)
	assert.Empty(t, decoy.Verdicts, "a correct guard stays at zero, got %v", ids(decoy.Verdicts))
}

func TestCollectPageLabClientSideFixtures(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	tests := []struct {
		name   string
		path   string
		wantID string
	}{
		{name: "hash sink", path: "/c02", wantID: "OR-C02"},
		{name: "reverse tabnabbing", path: "/f09", wantID: "OR-F09"},
		{name: "unsandboxed iframe", path: "/c03", wantID: "OR-C03"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			page, err := js.CollectPage(context.Background(), liveFetcher{}, srv.URL+tt.path)
			require.NoError(t, err)

			_, ok := verdictByID(page.Verdicts, tt.wantID)
			assert.True(t, ok, "missing %s in %v", tt.wantID, ids(page.Verdicts))
		})
	}
}

// liveFetcher talks to the in-process lab over plain net/http.
type liveFetcher struct{}

func (liveFetcher) Get(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= http.StatusBadRequest {
		return nil, errors.New("status " + resp.Status)
	}

	return io.ReadAll(resp.Body)
}
