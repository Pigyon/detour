package harvest

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Default per-source wall-clock limits. Without them a single source that
// never answers hangs the whole harvest forever: --budget bounds the attack,
// not this stage, so a run with no budget set would sit at zero percent CPU
// indefinitely waiting on, for example, an archive host that accepted the
// connection and then went silent.
const (
	defaultSourceTimeout = 30 * time.Second
	defaultCrawlTimeout  = 5 * time.Minute
)

// Options configures a harvest run.
type Options struct {
	// Passive keeps the run entirely off the target: archives only, not one
	// request to the host under test.
	Passive bool
	// Providers overrides the archive sources. Nil uses the keyless defaults.
	Providers []Provider
	// Crawler is the optional crawl stage. Nil skips it.
	Crawler Crawler
	// Archives is the client used for archive services. They are detour's own
	// data sources rather than the target, so they get a client whose scope
	// allowlist is the archive hosts. Nil falls back to the target client,
	// which a scope file will then lock out.
	Archives Doer
	// SourceTimeout bounds a single archive or freebies source. Zero uses the
	// default. The crawl gets its own, longer limit.
	SourceTimeout time.Duration
	// CrawlTimeout bounds the crawl, which legitimately takes longer than a
	// single archive fetch because it walks many pages. Zero uses the default.
	CrawlTimeout time.Duration
}

// Crawler walks a target for URLs. Declared here because this is where it is
// consumed, which keeps the crawl implementation swappable in tests.
type Crawler interface {
	Crawl(ctx context.Context, target string) ([]string, error)
}

// Result is everything a harvest found, with the failures kept rather than
// swallowed so a run never looks complete when it was not.
type Result struct {
	URLs    []string `json:"urls"`
	Sources []string `json:"sources"`
	Errors  []string `json:"errors,omitempty"`
}

// Harvester pulls URLs for a domain from every source it has.
type Harvester struct {
	client        Doer
	providers     []Provider
	crawler       Crawler
	passive       bool
	sourceTimeout time.Duration
	crawlTimeout  time.Duration
}

// New builds a harvester. A nil provider list uses the keyless defaults.
func New(client Doer, opts Options) *Harvester {
	archives := opts.Archives
	if archives == nil {
		archives = client
	}

	providers := opts.Providers
	if providers == nil {
		providers = DefaultProviders(archives)
	}

	sourceTimeout := opts.SourceTimeout
	if sourceTimeout <= 0 {
		sourceTimeout = defaultSourceTimeout
	}

	crawlTimeout := opts.CrawlTimeout
	if crawlTimeout <= 0 {
		crawlTimeout = defaultCrawlTimeout
	}

	return &Harvester{
		client:        client,
		providers:     providers,
		crawler:       opts.Crawler,
		passive:       opts.Passive,
		sourceTimeout: sourceTimeout,
		crawlTimeout:  crawlTimeout,
	}
}

// Run collects URLs for domain.
//
// Archives run concurrently with each other but serially within a provider,
// each at its own pace. Common Crawl in particular punishes bursty traffic,
// so its own rate governs it regardless of how fast the others go.
func (h *Harvester) Run(ctx context.Context, domain, base string) Result {
	result := Result{URLs: []string{}, Sources: []string{}, Errors: []string{}}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)

	for _, provider := range h.providers {
		wg.Add(1)

		go func(p Provider) {
			defer wg.Done()

			urls, err := h.fromProvider(ctx, p, domain)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", p.Name(), err))

				return
			}

			result.URLs = append(result.URLs, urls...)
			result.Sources = append(result.Sources, p.Name())
		}(provider)
	}

	wg.Wait()

	if h.passive {
		return result
	}

	h.active(ctx, base, &result)

	return result
}

// fromProvider applies the source's own pacing before its request.
func (h *Harvester) fromProvider(ctx context.Context, p Provider, domain string) ([]string, error) {
	if gap := p.Rate(); gap > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(gap):
		}
	}

	slog.Debug("harvesting archive", "provider", p.Name(), "domain", domain)

	fetchCtx, cancel := context.WithTimeout(ctx, h.sourceTimeout)
	defer cancel()

	return p.Fetch(fetchCtx, domain)
}

// active is everything that touches the target itself, skipped under
// --passive.
func (h *Harvester) active(ctx context.Context, base string, result *Result) {
	if base == "" {
		return
	}

	freebieCtx, cancelFreebies := context.WithTimeout(ctx, h.sourceTimeout)
	freebies, errs := Freebies(freebieCtx, h.client, base)

	cancelFreebies()

	if len(freebies) > 0 {
		result.URLs = append(result.URLs, freebies...)
		result.Sources = append(result.Sources, "freebies")
	}

	for _, err := range errs {
		result.Errors = append(result.Errors, err.Error())
	}

	if h.crawler == nil {
		return
	}

	crawlCtx, cancelCrawl := context.WithTimeout(ctx, h.crawlTimeout)
	defer cancelCrawl()

	crawled, err := h.crawler.Crawl(crawlCtx, base)
	if err != nil {
		result.Errors = append(result.Errors, "crawl: "+err.Error())

		return
	}

	result.URLs = append(result.URLs, crawled...)
	result.Sources = append(result.Sources, "crawl")
}
