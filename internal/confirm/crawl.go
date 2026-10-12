package confirm

import (
	"context"
	"log/slog"
	"net/url"
)

// Crawl drives the authenticated browser to each seed, lets each page run its
// JavaScript, and returns the in-scope URLs the browser actually requested
// that carry a query string. On a single-page app the real redirect surface
// (nav routes, XHR and fetch calls) is built at runtime and never appears in
// the server HTML a static harvest reads, so this is how those injection
// points are discovered at all.
//
// It is best-effort: a seed that fails to load is skipped rather than failing
// the crawl, and the browser's own scope guard still blocks every off-scope or
// canary request, so a seed can only ever surface in-scope URLs.
func (c *Confirmer) Crawl(ctx context.Context, seeds []string) []string {
	seen := make(map[string]struct{})
	out := []string{}

	for _, seed := range seeds {
		if ctx.Err() != nil {
			break
		}

		res, err := c.Visit(ctx, seed)
		if err != nil {
			slog.Debug("crawl seed failed", "seed", seed, "reason", err)

			continue
		}

		for _, candidate := range injectionCandidates(res.Chain) {
			if _, dup := seen[candidate]; dup {
				continue
			}

			seen[candidate] = struct{}{}
			out = append(out, candidate)
		}
	}

	return out
}

// injectionCandidates keeps the chain hops worth attacking: a URL the browser
// actually requested (not a blocked intent) that carries at least one query
// parameter, which is where an open redirect hides. The hops are already
// in-scope, since the recorder blocks everything else before it reaches here.
func injectionCandidates(chain []Hop) []string {
	out := []string{}

	for _, hop := range chain {
		if hop.Kind == HopBlocked {
			continue
		}

		parsed, err := url.Parse(hop.URL)
		if err != nil || parsed.RawQuery == "" {
			continue
		}

		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			continue
		}

		out = append(out, hop.URL)
	}

	return out
}
