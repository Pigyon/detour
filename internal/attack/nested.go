package attack

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/payload"
	"github.com/nedlir/detour/internal/resolve"
)

const (
	// techniqueNestedRedirectURI is a registered redirect_uri carrying a
	// destination the prefix check never examined.
	techniqueNestedRedirectURI = "OR-F01"
	// techniqueFetcherChain is a server-side fetcher that follows redirects
	// after its allowlist has already passed.
	techniqueFetcherChain = "OR-F07"

	// maxFetchBody bounds what is read back from a fetcher when comparing two
	// responses.
	maxFetchBody = 1 << 18

	// missingPath is the control value for the fetcher probe: a path no target
	// serves, so a constant error page gives itself away.
	missingPath = "/detour-control-does-not-exist"
)

// oauthParams carry a registered callback that a prefix check is likely to
// guard. Ordered so a report is the same between two runs of the same scan.
var oauthParams = []string{"redirect_uri", "post_logout_redirect_uri", "callback"}

// fetcherPaths mark an endpoint that retrieves a URL server side.
var fetcherPaths = []string{
	"fetch", "proxy", "preview", "render", "thumbnail", "screenshot",
	"image", "import", "webhook", "unfurl",
}

// nestedTemplates hang a destination off a registered callback. Both joiners
// are tried because the registered value may already carry a query.
var nestedTemplates = []string{"?next=https://", "&next=https://"}

// attackNestedRedirectURI reports an authorization endpoint whose prefix check
// accepts its own registered value with a destination appended.
func (e *Engine) attackNestedRedirectURI(ctx context.Context, parsed *url.URL) []model.Finding {
	hits := []model.Finding{}
	query := parsed.Query()

	for _, name := range oauthParams {
		actual, ok := lookupQuery(query, name)
		if !ok {
			continue
		}

		registered := query.Get(actual)
		if registered == "" {
			continue
		}

		if f, ok := e.nestedAttempt(ctx, parsed, actual, registered); ok {
			hits = append(hits, f)
		}
	}

	return hits
}

// nestedAttempt requires the appended destination to survive into the
// Location, and the independent second canary to survive the same way.
func (e *Engine) nestedAttempt(ctx context.Context, parsed *url.URL, param, registered string) (model.Finding, bool) {
	alt := AltCanary(e.canary)

	for _, joiner := range nestedTemplates {
		nested := registered + joiner + e.canary + "/"
		altNested := registered + joiner + alt + "/"

		loc, ok := e.nextLocation(ctx, withParam(parsed, param, nested))
		if !ok || !strings.Contains(loc, e.canary) {
			continue
		}

		altLoc, ok := e.nextLocation(ctx, withParam(parsed, param, altNested))
		if !ok || !strings.Contains(altLoc, alt) {
			continue
		}

		pr := probe{
			source:   parsed.String(),
			probed:   withParam(parsed, param, nested),
			expanded: nested,
			param:    param,
			payload:  payload.Payload{Technique: techniqueNestedRedirectURI, Mechanism: mechQuery},
		}

		f := e.finding(pr, resolve.Pair{}, dest{url: loc}, http.StatusFound)
		f.TechniqueID = techniqueNestedRedirectURI
		f.Verdict = model.VerdictCandidate
		// The Location goes to the registered callback, not off-site. What was
		// shown is that the prefix check ignores what rides along with it.
		f.Capabilities.RedirectExternal = false
		f.Capabilities.OAuthRedirectURI = true
		f.Candidate.Capabilities = f.Capabilities
		f.Evidence = append(f.Evidence,
			"registered="+registered,
			"note=the prefix check accepts its own registered value with a destination appended; the second leg depends on the callback, which detour does not drive",
		)

		return f, true
	}

	return model.Finding{}, false
}

// attackFetcherChain reports a server-side fetcher that keeps following
// redirects after its allowlist has passed.
func (e *Engine) attackFetcherChain(ctx context.Context, parsed *url.URL) []model.Finding {
	if len(e.chainTargets) == 0 || !isFetcherPath(parsed.EscapedPath()) {
		return nil
	}

	hits := []model.Finding{}
	query := parsed.Query()

	for _, actual := range targetParams(query) {
		if isHostParam(actual) {
			continue
		}

		if f, ok := e.fetcherAttempt(ctx, parsed, actual); ok {
			hits = append(hits, f)
		}
	}

	return hits
}

// fetcherAttempt submits a chain start and the chain's own terminal. A fetcher
// that returns the same body for both followed the redirects itself.
func (e *Engine) fetcherAttempt(ctx context.Context, parsed *url.URL, param string) (model.Finding, bool) {
	for _, target := range e.chainTargets {
		if target.Param != "" {
			continue
		}

		terminal, hops, ok := e.walkStatic(ctx, parsed, target.Path)
		if !ok || hops < 2 {
			continue
		}

		viaChain, ok := e.fetchBody(ctx, withParam(parsed, param, target.Path))
		if !ok {
			continue
		}

		direct, ok := e.fetchBody(ctx, withParam(parsed, param, terminal))
		if !ok || !bytes.Equal(viaChain, direct) {
			continue
		}

		// Two identical bodies prove nothing on their own: a fetcher that
		// renders one "could not retrieve that url" page for everything it
		// cannot handle matches trivially, having fetched nothing. The control
		// is a path that does not exist, and it has to come back different.
		control, ok := e.fetchBody(ctx, withParam(parsed, param, missingPath))
		if ok && bytes.Equal(control, viaChain) {
			continue
		}

		pr := probe{
			source:   parsed.String(),
			probed:   withParam(parsed, param, target.Path),
			expanded: target.Path,
			param:    param,
			payload:  payload.Payload{Technique: techniqueFetcherChain, Mechanism: mechQuery},
		}

		f := e.finding(pr, resolve.Pair{}, dest{url: terminal}, http.StatusOK)
		f.TechniqueID = techniqueFetcherChain
		f.Verdict = model.VerdictCandidate
		// Nothing left the target's own host, so no external redirect was
		// demonstrated. The finding is that the fetcher follows at all.
		f.Capabilities.RedirectExternal = false
		f.Capabilities.SSRFChain = true
		f.Capabilities.HopCount = hops
		f.Candidate.Capabilities = f.Capabilities
		f.Evidence = append(f.Evidence,
			"chain_start="+target.Path,
			"chain_terminal="+terminal,
			"note=the allowlist is evaluated once, on the submitted url, and the fetcher then follows redirects; detour proves this with hops inside the target and never aims one at an internal address",
		)

		return f, true
	}

	return model.Finding{}, false
}

// walkStatic follows a parameterless same-host redirector to its terminal,
// reporting how many hops it took.
func (e *Engine) walkStatic(ctx context.Context, parsed *url.URL, path string) (string, int, bool) {
	base := parsed.Scheme + "://" + parsed.Host
	origin := resolve.CanonicalHost(parsed.Hostname())
	current := base + path
	hops := 0
	seen := map[string]struct{}{}

	for hops < maxHops {
		loc, ok := e.nextLocation(ctx, current)
		if !ok {
			break
		}

		next, err := url.Parse(current)
		if err != nil {
			return "", 0, false
		}

		ref, err := url.Parse(loc)
		if err != nil {
			return "", 0, false
		}

		resolved := next.ResolveReference(ref)
		if resolve.CanonicalHost(resolved.Hostname()) != origin {
			return "", 0, false
		}

		if _, loop := seen[resolved.String()]; loop {
			return "", 0, false
		}

		seen[resolved.String()] = struct{}{}
		current = resolved.String()
		hops++
	}

	if hops == 0 {
		return "", 0, false
	}

	return strings.TrimPrefix(current, base), hops, true
}

// fetchBody reads a bounded response body.
func (e *Engine) fetchBody(ctx context.Context, raw string) ([]byte, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, false
	}

	resp, err := e.client.Do(ctx, req)
	if err != nil {
		return nil, false
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBody))
	if err != nil || len(body) == 0 {
		return nil, false
	}

	return body, true
}

func isFetcherPath(path string) bool {
	lower := strings.ToLower(path)

	for _, marker := range fetcherPaths {
		if strings.Contains(lower, marker) {
			return true
		}
	}

	return false
}
