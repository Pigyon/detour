// Package harvest collects URLs for a target from public archives, from the
// files a site publishes about itself, and from a crawl.
package harvest

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Provider is one source of archived URLs. Declared here because this is
// where it is consumed, and it keeps each source independently testable
// against a recorded fixture.
type Provider interface {
	// Name identifies the source in logs and errors.
	Name() string
	// Fetch returns whatever URLs the source knows for domain.
	Fetch(ctx context.Context, domain string) ([]string, error)
	// Rate is the minimum gap between requests this source tolerates.
	Rate() time.Duration
}

const (
	// maxArchiveBytes caps a single archive response. Archive dumps for a
	// large domain are unbounded otherwise.
	maxArchiveBytes = 64 << 20
	// archiveLimit caps how many rows are requested from each source.
	archiveLimit = 10000
)

// Doer issues an HTTP request. The scoped client satisfies it, which is how
// archive traffic stays inside the same boundary as everything else.
type Doer interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

// DefaultProviders are the keyless sources. VirusTotal and a keyed urlscan
// account are deliberately absent: they belong with the other keyed
// integrations, and detour has to be useful with no keys at all.
func DefaultProviders(c Doer) []Provider {
	return []Provider{
		&wayback{client: c},
		&commonCrawl{client: c},
		&otx{client: c},
		&urlscan{client: c},
	}
}

// wayback reads the Internet Archive CDX index.
type wayback struct{ client Doer }

func (w *wayback) Name() string { return "wayback" }

// Rate is modest. The CDX endpoint is tolerant but shared.
func (w *wayback) Rate() time.Duration { return 200 * time.Millisecond }

func (w *wayback) Fetch(ctx context.Context, domain string) ([]string, error) {
	endpoint := "https://web.archive.org/cdx/search/cdx?" + url.Values{
		"url":           {"*." + domain + "/*"},
		"output":        {"text"},
		"fl":            {"original"},
		"collapse":      {"urlkey"},
		"limit":         {strconv.Itoa(archiveLimit)},
		"filter":        {"statuscode:200"},
		"pageSize":      {"5"},
		"showDupeCount": {"false"},
	}.Encode()

	body, err := fetchBody(ctx, w.client, endpoint)
	if err != nil {
		return nil, err
	}

	return splitLines(body), nil
}

// commonCrawl reads the most recent Common Crawl index.
//
// Its rate is deliberately the slowest of the four. Common Crawl throttles
// hard and punishes bursty traffic, which is the single most important
// per-provider difference in this stage.
type commonCrawl struct{ client Doer }

func (c *commonCrawl) Name() string { return "commoncrawl" }

func (c *commonCrawl) Rate() time.Duration { return 1500 * time.Millisecond }

// ccIndex is one entry in the Common Crawl collection list.
type ccIndex struct {
	ID     string `json:"id"`
	CDXAPI string `json:"cdx-api"`
}

func (c *commonCrawl) Fetch(ctx context.Context, domain string) ([]string, error) {
	raw, err := fetchBody(ctx, c.client, "https://index.commoncrawl.org/collinfo.json")
	if err != nil {
		return nil, err
	}

	var indexes []ccIndex
	if err := json.Unmarshal(raw, &indexes); err != nil {
		return nil, fmt.Errorf("decoding commoncrawl index list: %w", err)
	}

	if len(indexes) == 0 || indexes[0].CDXAPI == "" {
		return nil, nil
	}

	endpoint := indexes[0].CDXAPI + "?" + url.Values{
		"url":    {"*." + domain + "/*"},
		"output": {"json"},
		"fl":     {"url"},
		"limit":  {strconv.Itoa(archiveLimit)},
	}.Encode()

	body, err := fetchBody(ctx, c.client, endpoint)
	if err != nil {
		return nil, err
	}

	return jsonLinesField(body, "url"), nil
}

// otx reads AlienVault OTX, which is keyless for this endpoint.
type otx struct{ client Doer }

func (o *otx) Name() string { return "otx" }

func (o *otx) Rate() time.Duration { return 300 * time.Millisecond }

type otxPage struct {
	URLList []struct {
		URL string `json:"url"`
	} `json:"url_list"`
	HasNext bool `json:"has_next"`
}

func (o *otx) Fetch(ctx context.Context, domain string) ([]string, error) {
	endpoint := "https://otx.alienvault.com/api/v1/indicators/domain/" +
		url.PathEscape(domain) + "/url_list?limit=500&page=1"

	body, err := fetchBody(ctx, o.client, endpoint)
	if err != nil {
		return nil, err
	}

	var page otxPage
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("decoding otx response: %w", err)
	}

	out := make([]string, 0, len(page.URLList))
	for _, item := range page.URLList {
		out = append(out, item.URL)
	}

	return out, nil
}

// urlscan reads the public urlscan.io search, which works without a key at a
// reduced rate.
type urlscan struct{ client Doer }

func (u *urlscan) Name() string { return "urlscan" }

func (u *urlscan) Rate() time.Duration { return 1000 * time.Millisecond }

type urlscanPage struct {
	Results []struct {
		Page struct {
			URL string `json:"url"`
		} `json:"page"`
	} `json:"results"`
}

func (u *urlscan) Fetch(ctx context.Context, domain string) ([]string, error) {
	endpoint := "https://urlscan.io/api/v1/search/?" + url.Values{
		"q":    {"domain:" + domain},
		"size": {"1000"},
	}.Encode()

	body, err := fetchBody(ctx, u.client, endpoint)
	if err != nil {
		return nil, err
	}

	var page urlscanPage
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("decoding urlscan response: %w", err)
	}

	out := make([]string, 0, len(page.Results))
	for _, item := range page.Results {
		out = append(out, item.Page.URL)
	}

	return out, nil
}

func fetchBody(ctx context.Context, client Doer, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("building archive request: %w", err)
	}

	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", endpoint, err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("fetching %s: status %d", endpoint, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxArchiveBytes))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", endpoint, err)
	}

	return body, nil
}

func splitLines(body []byte) []string {
	out := []string{}
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			out = append(out, line)
		}
	}

	return out
}

// jsonLinesField reads a stream of one JSON object per line and pulls one
// field out of each. Common Crawl answers in this shape.
func jsonLinesField(body []byte, field string) []string {
	out := []string{}

	for _, line := range splitLines(body) {
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}

		if value, ok := row[field].(string); ok && value != "" {
			out = append(out, value)
		}
	}

	return out
}
