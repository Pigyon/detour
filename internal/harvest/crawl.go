package harvest

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/nedlir/detour/internal/js"
	"golang.org/x/net/html"
)

const (
	// defaultCrawlDepth is deliberately shallow. The goal is finding parameter
	// shapes, not mirroring a site.
	defaultCrawlDepth = 3
	// defaultMaxPages bounds a crawl regardless of depth, which is what
	// actually stops one on a site with infinite URL space.
	defaultMaxPages = 300
	// defaultCrawlConcurrency bounds in-flight fetches.
	defaultCrawlConcurrency = 5
)

// CrawlOptions configures the crawl stage.
type CrawlOptions struct {
	Depth    int
	MaxPages int
	// JSCrawl reads scripts for endpoint strings as well as following links.
	// This is what finds endpoints that exist only inside a bundle.
	JSCrawl bool
	// SameHost keeps the crawler on the host it started from.
	SameHost    bool
	Concurrency int
}

// WebCrawler walks a target for URLs. It satisfies Crawler.
//
// This is detour's own crawler rather than katana. katana depends on jsluice,
// which depends on tree-sitter, which is cgo only, and that breaks the static
// core binary and cross-compilation. The JS awareness that made katana worth
// embedding is available here anyway: the same analyzer that reads navigation
// sinks also reports the endpoint strings a bundle contains.
type WebCrawler struct {
	client Doer
	opts   CrawlOptions
}

// compile-time check that the concrete crawler satisfies the consumer's
// contract.
var _ Crawler = (*WebCrawler)(nil)

// NewCrawler returns a crawler with sane depth and pacing defaults.
func NewCrawler(client Doer, opts CrawlOptions) *WebCrawler {
	if opts.Depth <= 0 {
		opts.Depth = defaultCrawlDepth
	}

	if opts.MaxPages <= 0 {
		opts.MaxPages = defaultMaxPages
	}

	if opts.Concurrency <= 0 {
		opts.Concurrency = defaultCrawlConcurrency
	}

	return &WebCrawler{client: client, opts: opts}
}

// Crawl walks target breadth first and returns every URL it saw.
func (c *WebCrawler) Crawl(ctx context.Context, target string) ([]string, error) {
	root, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parsing crawl target: %w", err)
	}

	state := &crawlState{
		seen:  map[string]struct{}{target: {}},
		found: []string{},
	}

	frontier := []string{target}

	for depth := 0; depth <= c.opts.Depth && len(frontier) > 0; depth++ {
		next := c.sweep(ctx, root, frontier, state)
		if state.budgetSpent(c.opts.MaxPages) || cancelled(ctx) {
			break
		}

		frontier = next
	}

	// A cancelled or budget-capped crawl still returns what it saw. Partial
	// results are the normal outcome here, not a failure.
	return state.results(), nil
}

// cancelled keeps the loop condition readable and, more usefully, keeps a
// cancelled context from looking like an error the crawl should return. A
// partial crawl is a normal outcome.
func cancelled(ctx context.Context) bool {
	return ctx.Err() != nil
}

// crawlState is the shared bookkeeping for one crawl.
type crawlState struct {
	mu      sync.Mutex
	seen    map[string]struct{}
	found   []string
	fetched int
}

// take reserves one page of the fetch budget.
func (s *crawlState) take(maxPages int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.fetched >= maxPages {
		return false
	}

	s.fetched++

	return true
}

func (s *crawlState) budgetSpent(maxPages int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.fetched >= maxPages
}

// record keeps the URLs not seen before and returns them for the next depth.
func (s *crawlState) record(links []string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	fresh := []string{}

	for _, link := range links {
		if _, dup := s.seen[link]; dup {
			continue
		}

		s.seen[link] = struct{}{}
		s.found = append(s.found, link)
		fresh = append(fresh, link)
	}

	return fresh
}

func (s *crawlState) results() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string{}, s.found...)
}

// sweep fetches one depth level and returns the next frontier.
func (c *WebCrawler) sweep(ctx context.Context, root *url.URL, pages []string, state *crawlState) []string {
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		next = []string{}
		sem  = make(chan struct{}, c.opts.Concurrency)
	)

	for _, page := range pages {
		if !state.take(c.opts.MaxPages) {
			break
		}

		wg.Add(1)

		go func(page string) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			fresh := state.record(c.visit(ctx, root, page))

			mu.Lock()

			next = append(next, fresh...)
			mu.Unlock()
		}(page)
	}

	wg.Wait()

	return next
}

// visit fetches one page and returns the in-scope URLs it references.
func (c *WebCrawler) visit(ctx context.Context, root *url.URL, page string) []string {
	body, err := fetchBody(ctx, c.client, page)
	if err != nil {
		return nil
	}

	out := c.linksFrom(root, page, body)

	if c.opts.JSCrawl {
		out = append(out, c.scriptsFrom(ctx, root, page, body)...)
	}

	return c.keepInScope(root, out)
}

// linkAttrs are the attributes that name another URL.
var linkAttrs = map[string][]string{
	"a":      {"href"},
	"link":   {"href"},
	"area":   {"href"},
	"form":   {"action"},
	"iframe": {"src"},
	"frame":  {"src"},
	"script": {"src"},
}

func (c *WebCrawler) linksFrom(root *url.URL, page string, body []byte) []string {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil
	}

	base := baseOf(page, root)
	out := []string{}

	var walk func(*html.Node)

	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			out = append(out, nodeLinks(base, n)...)
		}

		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}

	walk(doc)

	return out
}

func nodeLinks(base *url.URL, n *html.Node) []string {
	out := []string{}

	for _, name := range linkAttrs[n.Data] {
		for _, attr := range n.Attr {
			if !strings.EqualFold(attr.Key, name) {
				continue
			}

			if resolved, ok := resolveAgainst(base, attr.Val); ok {
				out = append(out, resolved)
			}
		}
	}

	return out
}

// scriptsFrom reads the page's scripts for endpoint strings. A bundle names
// endpoints no link on the page points at, which is the whole reason the
// crawl stage needs to understand JavaScript at all.
func (c *WebCrawler) scriptsFrom(ctx context.Context, root *url.URL, page string, body []byte) []string {
	doc, err := js.ParseHTML(page, body)
	if err != nil {
		return nil
	}

	base := baseOf(page, root)
	out := []string{}

	for _, script := range doc.Scripts {
		code, source, ok := c.scriptBody(ctx, root, page, script)
		if !ok {
			continue
		}

		if script.Src != "" {
			out = append(out, SourceMaps(script.Src, code)...)
		}

		report, err := js.Analyze(source, code)
		if err != nil {
			continue
		}

		for _, endpoint := range report.URLs {
			if resolved, ok := resolveAgainst(base, endpoint); ok {
				out = append(out, resolved)
			}
		}
	}

	return out
}

func (c *WebCrawler) scriptBody(ctx context.Context, root *url.URL, page string, script js.Script) ([]byte, string, bool) {
	if script.Src == "" {
		return script.Body, page, true
	}

	if !c.inScope(root, script.Src) {
		return nil, "", false
	}

	fetched, err := fetchBody(ctx, c.client, script.Src)
	if err != nil {
		return nil, "", false
	}

	return fetched, script.Src, true
}

func (c *WebCrawler) keepInScope(root *url.URL, urls []string) []string {
	out := make([]string, 0, len(urls))

	for _, raw := range urls {
		if c.inScope(root, raw) {
			out = append(out, raw)
		}
	}

	return out
}

// inScope keeps the crawl on the host it started from when SameHost is set.
// The scope guard still governs every request regardless; this only stops the
// crawler wandering.
func (c *WebCrawler) inScope(root *url.URL, raw string) bool {
	if !c.opts.SameHost {
		return true
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}

	return strings.EqualFold(parsed.Hostname(), root.Hostname())
}

func baseOf(page string, root *url.URL) *url.URL {
	parsed, err := url.Parse(page)
	if err != nil {
		return root
	}

	return parsed
}
