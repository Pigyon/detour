package attack

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/nedlir/detour/internal/decode"
	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/payload"
	"github.com/nedlir/detour/internal/resolve"
)

// A redirector that only accepts destinations on its own host is not safe, it
// is one hop short. If any endpoint on that host is itself open, the pair
// completes the journey, and a scanner that stops at the first Location calls
// the outer one clean.

const (
	// maxHops bounds a chain. Two hops is the documented pattern; a third
	// covers a normalization bounce on the way, and beyond that a loop is far
	// more likely than a finding.
	maxHops = 4
)

// ChainTarget is a same-host redirector that can complete a hop for an outer
// redirector whose allowlist only permits its own host.
type ChainTarget struct {
	// Path is the endpoint path, rooted, for example "/b05/inner".
	Path string
	// Param is the parameter on it that carries a destination.
	Param string
}

// SetChainTargets tells the engine which same-host endpoints are themselves
// redirectors, so it can aim an outer redirector at one of them.
//
// In a full run these come from selection. Given none, the engine simply never
// produces the chained class rather than guessing at paths.
func (e *Engine) SetChainTargets(targets []ChainTarget) {
	e.chainTargets = append([]ChainTarget(nil), targets...)
}

// chainPayloads builds the relative destinations that point back at a known
// same-host redirector carrying the canary.
func (e *Engine) chainPayloads(canary string) []string {
	out := make([]string, 0, len(e.chainTargets))

	for _, target := range e.chainTargets {
		if target.Path == "" || target.Param == "" {
			continue
		}

		inner := url.Values{}
		inner.Set(target.Param, "https://"+canary+"/")
		out = append(out, target.Path+"?"+inner.Encode())
	}

	return out
}

// hop is one link in a followed redirect chain.
type hop struct {
	index int
	from  string
	to    string
}

// chainResult is what a followed chain proved.
type chainResult struct {
	hops   []hop
	pair   resolve.Pair
	found  dest
	status int
}

// followChain walks same-host redirects looking for the canary beyond the
// first hop.
//
// Only same-host hops are followed. A hop that leaves the origin is either the
// finding itself, already seen by the caller, or somebody else's server, and
// detour has no business fetching that.
func (e *Engine) followChain(ctx context.Context, base, loc, canary string) (chainResult, bool) {
	origin := originOf(base)
	if origin == "" {
		return chainResult{}, false
	}

	hops := []hop{}
	current := base
	next := loc
	seen := map[string]struct{}{}

	for index := 1; index <= maxHops; index++ {
		pair, err := resolve.Interpret(current, next)
		if err != nil || pair.RFC.Resolved == "" {
			return chainResult{hops: hops}, false
		}

		target := pair.RFC.Resolved
		if _, loop := seen[target]; loop {
			return chainResult{hops: hops}, false
		}

		seen[target] = struct{}{}
		hops = append(hops, hop{index: index, from: current, to: target})

		// Anything off-origin is the caller's business, not another request.
		if pair.RFC.Host != origin {
			return chainResult{hops: hops}, false
		}

		pairNext, found, status, err := e.readDest(ctx, target, nil, canary)
		if err != nil {
			return chainResult{hops: hops}, false
		}

		if found.url != "" && (found.quirk || resolve.HitsCanary(pairNext, canary)) {
			hops = append(hops, hop{index: index + 1, from: target, to: found.url})

			return chainResult{hops: hops, pair: pairNext, found: found, status: status}, true
		}

		following, ok := e.nextLocation(ctx, target)
		if !ok {
			return chainResult{hops: hops}, false
		}

		current, next = target, following
	}

	return chainResult{hops: hops}, false
}

// nextLocation reads the Location of one same-host hop.
func (e *Engine) nextLocation(ctx context.Context, raw string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return "", false
	}

	resp, err := e.client.Do(ctx, req)
	if err != nil {
		return "", false
	}

	defer func() { _ = resp.Body.Close() }()

	loc := resp.Header.Get("Location")

	return loc, loc != ""
}

// intermediates names the same-host hops a chain passed through, for a report
// that has to say which endpoint completed the journey.
func intermediates(hops []hop) string {
	parts := make([]string, 0, len(hops))
	for _, h := range hops {
		parts = append(parts, h.to)
	}

	return strings.Join(parts, " -> ")
}

func originOf(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}

	return resolve.CanonicalHost(u.Hostname())
}

// chainFinding builds the OR-B05 record for a canary reached past the first
// hop.
func (e *Engine) chainFinding(pr probe, result chainResult) model.Finding {
	f := e.finding(pr, result.pair, result.found, result.status)
	f.TechniqueID = techniqueChained
	f.Capabilities.HopCount = len(result.hops)
	f.Candidate.Capabilities = f.Capabilities
	f.Evidence = append(f.Evidence,
		"hops="+intermediates(result.hops),
		"note=the canary is reached only past the first hop; the outer allowlist is completed by a same-host redirector",
	)

	return f
}

// attackChain aims each redirect parameter at a known same-host redirector
// carrying the canary, then follows the hops.
func (e *Engine) attackChain(ctx context.Context, parsed *url.URL, cracked map[string]struct{}) []model.Finding {
	if len(e.chainTargets) == 0 {
		return nil
	}

	hits := []model.Finding{}
	query := parsed.Query()

	for _, actual := range targetParams(query) {
		if isHostParam(actual) {
			continue
		}

		// A parameter the direct payloads already walked through needs no
		// second leg, and probing one anyway is the expensive half of this
		// stage for no extra finding.
		if _, done := cracked[actual]; done {
			continue
		}

		primary := e.chainPayloads(e.canary)
		alternates := e.chainPayloads(AltCanary(e.canary))

		for i, nested := range primary {
			f, ok := e.chainAttempt(ctx, parsed, actual, nested, alternates[i])
			if !ok {
				continue
			}

			hits = append(hits, f)
		}
	}

	return hits
}

// chainAttempt probes one outer parameter with one nested destination and
// requires the independent second canary to travel the same route.
func (e *Engine) chainAttempt(ctx context.Context, parsed *url.URL, param, nested, alt string) (model.Finding, bool) {
	probed := withParam(parsed, param, nested)

	loc, ok := e.nextLocation(ctx, probed)
	if !ok {
		return model.Finding{}, false
	}

	result, ok := e.followChain(ctx, probed, loc, e.canary)
	if !ok || len(result.hops) < 2 {
		return model.Finding{}, false
	}

	altProbed := withParam(parsed, param, alt)

	altLoc, ok := e.nextLocation(ctx, altProbed)
	if !ok {
		return model.Finding{}, false
	}

	if _, ok := e.followChain(ctx, altProbed, altLoc, AltCanary(e.canary)); !ok {
		return model.Finding{}, false
	}

	return e.chainFinding(probe{
		source:    parsed.String(),
		probed:    probed,
		altProbed: altProbed,
		expanded:  nested,
		param:     param,
		payload:   payload.Payload{Technique: techniqueChained, Mechanism: mechQuery},
	}, result), true
}

// withParam returns u with one query parameter replaced.
func withParam(u *url.URL, name, value string) string {
	next := cloneURL(u)
	q := next.Query()
	q.Set(name, value)
	next.RawQuery = q.Encode()

	return next.String()
}

// maxChainTargets bounds how many same-host redirectors are tried as the
// second leg. Every one of them costs probes against every outer parameter,
// so this is quadratic work and the list has to stay short.
const (
	maxChainTargets = 8
	// maxChainedTargets is the share reserved for parameterized redirectors,
	// leaving the rest for the bare paths a multi-hop chain is built from.
	maxChainedTargets = 6
)

// redirectorSegments are the path segments an inner redirector is habitually
// named after. A target list capped at a handful has to be ranked by
// something, and on a real host the candidates number in the dozens.
var redirectorSegments = map[string]struct{}{
	"go": {}, "r": {}, "redirect": {}, "redir": {}, "out": {}, "link": {},
	"click": {}, "inner": {}, "jump": {}, "exit": {}, "away": {}, "to": {},
	"forward": {}, "track": {}, "url": {}, "goto": {}, "continue": {},
}

// numberedRedirector matches the r1, r2, u3 style hop names that chained
// redirectors are usually built from.
var numberedRedirector = regexp.MustCompile(`^[ru]\d+$`)

// ChainTargetsFrom derives candidate second-leg redirectors from the URLs a
// run already selected.
//
// A chained redirect needs an inner redirector on the allowlisted host, and
// selection has already found the endpoints on that host which carry a
// destination. Those are the candidates, so nothing has to be guessed and
// nothing extra has to be crawled. They are ranked because the list is capped
// well below the number of endpoints a real host offers.
func ChainTargetsFrom(urls []string) []ChainTarget {
	found := []scoredTarget{}
	seen := map[string]struct{}{}

	for _, raw := range urls {
		found = append(found, targetsIn(raw, seen)...)
	}

	slices.SortStableFunc(found, func(a, b scoredTarget) int {
		return b.score - a.score
	})

	// The two consumers want different things and must not starve each other.
	// Only a parameterized target can complete a chained redirect, and only a
	// bare path drives the fetcher probe, so each is guaranteed a reserve and
	// whatever the other leaves unused is shared out.
	parameterized := take(found, maxChainTargets, true)
	bare := take(found, maxChainTargets, false)

	reserved := min(len(parameterized), maxChainedTargets)
	bareCount := min(len(bare), maxChainTargets-reserved)
	paramCount := min(len(parameterized), maxChainTargets-bareCount)

	out := make([]ChainTarget, 0, paramCount+bareCount)
	out = append(out, parameterized[:paramCount]...)

	return append(out, bare[:bareCount]...)
}

// take returns up to limit targets, choosing only those that do or do not
// carry a parameter.
func take(found []scoredTarget, limit int, parameterized bool) []ChainTarget {
	out := []ChainTarget{}

	for _, candidate := range found {
		if len(out) >= limit {
			break
		}

		if (candidate.target.Param != "") != parameterized {
			continue
		}

		out = append(out, candidate.target)
	}

	return out
}

// scoredTarget is one ranked candidate second leg.
type scoredTarget struct {
	target ChainTarget
	score  int
}

// targetsIn reads the candidates one URL offers.
func targetsIn(raw string, seen map[string]struct{}) []scoredTarget {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Path == "" {
		return nil
	}

	path := parsed.EscapedPath()
	query := parsed.Query()
	out := []scoredTarget{}

	for _, actual := range targetParams(query) {
		if isHostParam(actual) {
			continue
		}

		if target, score, ok := scoreTarget(seen, path, actual); ok {
			out = append(out, scoredTarget{target: target, score: score})
		}
	}

	if len(out) > 0 || len(query) > 0 {
		return out
	}

	// An endpoint with no parameters can still be a hop: a static redirector
	// is what a multi-hop chain is usually built from.
	if target, score, ok := scoreTarget(seen, path, ""); ok && score > 0 {
		out = append(out, scoredTarget{target: target, score: score})
	}

	return out
}

// scoreTarget ranks one candidate, higher being more likely to be a
// redirector, and refuses one already recorded.
func scoreTarget(seen map[string]struct{}, path, param string) (ChainTarget, int, bool) {
	key := path + "\x00" + param
	if _, dup := seen[key]; dup {
		return ChainTarget{}, 0, false
	}

	seen[key] = struct{}{}

	score := 0

	for segment := range strings.SplitSeq(strings.ToLower(path), "/") {
		// A path carrying opaque state names one message, not a reusable
		// redirector. Chaining to it would replay somebody's tracking link.
		if token, _ := decode.StripSuffix(segment); decode.IsOpaque(token) {
			return ChainTarget{}, 0, false
		}

		if _, ok := redirectorSegments[segment]; ok {
			score += 2
		}

		if numberedRedirector.MatchString(segment) {
			score += 2
		}
	}

	if param != "" {
		score++
	}

	return ChainTarget{Path: path, Param: param}, score, true
}
