// Package attack fires templated payloads at navigation candidates and scores hits.
package attack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/nedlir/detour/internal/checkpoint"
	"github.com/nedlir/detour/internal/client"
	"github.com/nedlir/detour/internal/corpus"
	"github.com/nedlir/detour/internal/decode"
	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/payload"
	"github.com/nedlir/detour/internal/pool"
	"github.com/nedlir/detour/internal/resolve"
)

const (
	mechHeader  = payload.MechHeader
	mechCRLF    = payload.MechCRLF
	mechBlob    = payload.MechBlob
	mechQuery   = payload.MechQuery
	mechMeta    = payload.MechMeta
	mechRefresh = payload.MechRefresh
	mechPath    = payload.MechPath
	mechHost    = payload.MechHost

	// techniqueChained is the canary reached only past the first hop.
	techniqueChained = "OR-B05"

	// maxBodyScan is how much of a response body is read looking for a meta
	// refresh. The tag lives in the head, so this is generous.
	maxBodyScan = 1 << 20

	// maxParamValue bounds what is examined when deciding whether a parameter
	// value is a destination.
	maxParamValue = 2048

	// maxDerivedParams caps the parameters attacked purely because their value
	// looks like a destination, so one crowded URL cannot consume a run.
	maxDerivedParams = 8
)

// dest is one candidate destination and how the response conveyed it.
//
// The mechanism matters as much as the URL. A destination that arrived in a
// Refresh header is OR-D06 and one scraped from a meta tag is OR-C04,
// whichever payload happened to be in flight, and labelling both as whatever
// string got there loses the technique.
type dest struct {
	url       string
	mechanism string
	technique string
	// quirk marks a destination only a lenient parser reads as the canary,
	// because net/url refuses the string. Such a hit is candidate tier: a
	// same-origin check cannot settle which host a browser picks.
	quirk bool
	// scheme marks a script-bearing scheme that reached the sink. There is no
	// host to compare, so the arrival of the scheme is the finding.
	scheme bool
}

// redirectParams is the canonical list, shared with the classifier so the
// engine never skips a parameter selection just flagged as interesting.
var redirectParams = corpus.RedirectParams()

// hostParams carry a bare hostname that a framework interpolates into the
// destination's authority, rather than a whole URL. A payload wearing a scheme
// is wasted on them, and the bare-host payload is wasted everywhere else.
var hostParams = map[string]struct{}{
	"desthost": {}, "dest_host": {}, "host": {}, "hostname": {}, "domain": {},
}

// paramTechniques name the techniques defined by where the destination sits
// rather than by the payload that got through.
//
// A SAML RelayState that redirects is OR-D04 whichever string beat the
// validator, because the technique is the parameter's role in the protocol.
// Labelling it after the payload loses the only detail a triager needs.
var paramTechniques = map[string]string{
	"relaystate": "OR-D04",
}

// techniqueForParam returns the id a parameter's role implies, if any.
func techniqueForParam(name string) (string, bool) {
	id, ok := paramTechniques[strings.ToLower(name)]

	return id, ok
}

// targetParams names the parameters on one URL worth attacking: the ones whose
// name is redirect shaped, plus the ones whose current value is already a URL.
//
// The second half is the stronger signal of the two. A parameter called "q" or
// "u2" that today holds "https://target.example/account" is a destination the
// application itself put there, whatever it is named, and a list of known
// names can never cover it. The classifier scores this already; deriving it
// here as well means it also applies to a bare URL list, and means the two
// stages cannot disagree about which parameters matter.
func targetParams(query url.Values) []string {
	return targetParamsOn(query, false)
}

// targetParamsOn is targetParams, told whether the endpoint has already shown
// it redirects. On a proven redirector every parameter is a candidate.
func targetParamsOn(query url.Values, redirector bool) []string {
	seen := map[string]struct{}{}
	out := []string{}

	for _, name := range redirectParams {
		if actual, ok := lookupQuery(query, name); ok {
			if _, dup := seen[actual]; !dup {
				seen[actual] = struct{}{}

				out = append(out, actual)
			}
		}
	}

	// Derived parameters are capped. Each one costs roughly thirty requests,
	// and a URL carrying fifty of them would spend a whole scan's budget on
	// one endpoint. The name list above is the reliable signal; this is the
	// supplement.
	derived := 0

	for _, name := range sortedKeys(query) {
		if derived >= maxDerivedParams {
			break
		}

		if _, dup := seen[name]; dup {
			continue
		}

		if !looksLikeURL(query.Get(name)) && !redirector {
			continue
		}

		seen[name] = struct{}{}
		derived++

		out = append(out, name)
	}

	// Stable order, so two runs of the same scan report the same thing.
	sort.Strings(out)

	return out
}

// baselineKey records the redirector probe in the checkpoint under a name no
// technique uses, so a resumed run reaches the same conclusion without
// sending the request again.
const baselineKey = "baseline"

// baseline sends the source URL once and reports whether the endpoint answers
// with a destination, and whether it answered at all.
func (e *Engine) baseline(ctx context.Context, raw string) (redirector, reachable bool) {
	if e.checkpoint != nil && e.checkpoint.Seen(raw, baselineKey, baselineKey) {
		_, was := e.checkpoint.Recover(raw, baselineKey, baselineKey)

		return was, true
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return false, false
	}

	resp, err := e.client.Do(ctx, req)
	if err != nil {
		return false, false
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyScan))
	redirector = len(destValues(resp, body)) > 0

	e.recordBaseline(raw, redirector)

	return redirector, true
}

// recordBaseline stores the redirector verdict so a resume can read it back.
func (e *Engine) recordBaseline(raw string, redirector bool) {
	if e.checkpoint == nil {
		return
	}

	if !redirector {
		_ = e.checkpoint.RecordAttempt(raw, baselineKey, baselineKey, false)

		return
	}

	_ = e.checkpoint.RecordHit(raw, baselineKey, baselineKey, model.Finding{})
}

// sortedKeys returns a query's parameter names in a stable order.
func sortedKeys(query url.Values) []string {
	out := make([]string, 0, len(query))
	for name := range query {
		out = append(out, name)
	}

	sort.Strings(out)

	return out
}

// looksLikeURL reports whether a parameter value is already a destination.
//
// A protocol-relative value counts only when it names a host. Accepting a bare
// "//" made any parameter holding two slashes look like a destination, which
// is the cheapest possible way to inflate a scan.
func looksLikeURL(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxParamValue {
		return false
	}

	if rest, ok := strings.CutPrefix(value, "//"); ok {
		host, _, _ := strings.Cut(strings.TrimLeft(rest, "/"), "/")

		return strings.Contains(host, ".")
	}

	parsed, err := url.Parse(value)

	return err == nil && parsed.Hostname() != "" &&
		(parsed.Scheme == "http" || parsed.Scheme == "https")
}

func isHostParam(name string) bool {
	_, ok := hostParams[strings.ToLower(name)]

	return ok
}

// probe is one attack attempt: the request to send, the independent
// second-canary request that proves input control, and where it came from.
type probe struct {
	source    string
	probed    string
	altProbed string
	expanded  string
	payload   payload.Payload
	param     string
	extra     http.Header
	altExtra  http.Header
	// blob is set when the destination lives inside an opaque envelope.
	blob *blobContext
}

// blobContext carries what the decoder learned, so a blob finding names the
// envelope class and the exact field that moved.
type blobContext struct {
	technique string
	chain     []model.Decoder
	fields    []model.FieldPath
	field     model.FieldPath
	strategy  decode.Strategy
}

// Coverage is what a run actually touched, so a count of zero can be read.
//
// "0 findings" on its own says nothing: it is the same output whether the
// target was clean, unreachable, or had no parameter worth probing. These
// numbers separate those cases without the operator having to rerun at debug.
type Coverage struct {
	// Sources is how many URLs were handed to the engine.
	Sources int
	// Reachable is how many of them answered the baseline request.
	Reachable int
	// Redirectors is how many already answered with a destination.
	Redirectors int
	// Params is how many distinct parameters were probed.
	Params int
	// RedirectorURLs names the sources Redirectors counted.
	//
	// An endpoint that already redirects is the best lead --deep has: it is
	// a confirmed redirector, not a hypothetical one, and worth brute-forcing
	// parameters on before anything else in the harvest. A bare count threw
	// that away the moment the run finished.
	RedirectorURLs []string
}

// Engine probes candidates with the built-in payload set.
type Engine struct {
	client       *client.Client
	canary       string
	keyword      string
	payloads     []payload.Payload
	concurrency  int
	coverage     Coverage
	coverageMu   sync.Mutex
	checkpoint   *checkpoint.Store
	chainTargets []ChainTarget
	trustedHosts []string
}

// SetTrustedHosts supplies hosts a validator is known to allow, as read out of
// client-side guards by the js stage. Payloads that have to wear a trusted
// name are tried against each one.
func (e *Engine) SetTrustedHosts(hosts []string) {
	e.trustedHosts = append([]string(nil), hosts...)
}

// New builds an engine. payloads may be nil to use payload.BuiltIn.
func New(c *client.Client, canary, keyword string, concurrency int, payloads []payload.Payload) *Engine {
	if keyword == "" {
		keyword = payload.DefaultKeyword
	}

	if concurrency < 1 {
		concurrency = 1
	}

	if payloads == nil {
		payloads = payload.BuiltIn()
	}

	return &Engine{
		client:      c,
		canary:      canary,
		keyword:     keyword,
		payloads:    payloads,
		concurrency: concurrency,
	}
}

// Coverage reports what the last Run touched.
func (e *Engine) Coverage() Coverage {
	e.coverageMu.Lock()
	defer e.coverageMu.Unlock()

	return e.coverage
}

func (e *Engine) noteCoverage(reachable, redirector bool, params int, source string) {
	e.coverageMu.Lock()
	defer e.coverageMu.Unlock()

	e.coverage.Sources++

	if reachable {
		e.coverage.Reachable++
	}

	if redirector {
		e.coverage.Redirectors++
		e.coverage.RedirectorURLs = append(e.coverage.RedirectorURLs, source)
	}

	e.coverage.Params += params
}

// SetCheckpoint records attempts so --resume can skip completed work.
func (e *Engine) SetCheckpoint(store *checkpoint.Store) {
	e.checkpoint = store
}

// The input_controlled check needs a second, independent destination: if only
// one is ever reflected, the endpoint may simply redirect there always.
//
// The second destination has to be as acceptable to the target as the first.
// A target that checks its destination at all (rejects reserved TLDs, or
// requires a host that resolves, which is what a link shortener does) will
// take a real domain and refuse a .invalid one, and then a fully vulnerable
// endpoint reports nothing at all. So the alt mirrors the primary's nature
// rather than being pinned to one name.
var (
	// reservedTLDs never resolve, by RFC 2606 and RFC 6761.
	reservedTLDs = []string{".invalid", ".test", ".example", ".localhost"}

	// altResolving are IANA-reserved documentation domains. They resolve, so
	// they satisfy a target that checks, and they belong to nobody, so
	// pointing a payload at one implicates no third party.
	altResolving = []string{"example.com", "example.net"}

	// altReserved are used when the primary destination does not resolve
	// either, keeping a run entirely free of real names.
	altReserved = []string{"detour-alt.invalid", "detour-alt2.invalid"}
)

// AltCanary returns a destination distinct from primary under the same
// suffix-aware comparison a finding is judged by.
func AltCanary(primary string) string {
	candidates := altResolving
	if isReservedName(primary) {
		candidates = altReserved
	}

	for _, candidate := range candidates {
		if !related(candidate, primary) {
			return candidate
		}
	}

	return altReserved[0]
}

// isReservedName reports whether a host is one that cannot resolve.
func isReservedName(host string) bool {
	lower := strings.ToLower(host)
	for _, tld := range reservedTLDs {
		if strings.HasSuffix(lower, tld) {
			return true
		}
	}

	return false
}

// related reports whether two destinations would match each other under the
// canary check, which would let the second probe agree with the first for free.
func related(a, b string) bool {
	return resolve.HostSuffix(a, b) || resolve.HostSuffix(b, a)
}

// Run attacks every source URL and returns capability-scored findings.
func (e *Engine) Run(ctx context.Context, sources []string) ([]model.Finding, error) {
	var (
		mu       sync.Mutex
		findings = []model.Finding{}
	)

	err := pool.Run(ctx, e.concurrency, sources, func(ctx context.Context, raw string) error {
		slog.Debug("attacking source", "url", raw)

		hits, err := e.attackOne(ctx, raw)

		for _, f := range hits {
			slog.Debug("finding",
				"technique", f.TechniqueID,
				"mechanism", f.Mechanism,
				"param", f.Candidate.ParamName,
				"payload", f.Payload)
		}

		// A source keeps what it proved even when it did not finish. The
		// alternative threw the whole source away over its last request.
		if len(hits) > 0 {
			mu.Lock()

			findings = append(findings, hits...)
			mu.Unlock()
		}

		return err
	})

	mu.Lock()
	defer mu.Unlock()

	if err != nil && !stopped(err) {
		return nil, err
	}

	return findings, err
}

// stopped reports whether err is the run being stopped rather than failing.
//
// An interrupted scan is not a failed scan. Ctrl-C used to return no findings,
// write no report, and exit non-zero, so stopping a forty-minute run cost the
// whole forty minutes unless --resume happened to be set.
func stopped(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func (e *Engine) attackOne(ctx context.Context, raw string) ([]model.Finding, error) {
	if payload.HasKeyword(raw, e.keyword) {
		return e.attackKeyword(ctx, raw)
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing source: %w", err)
	}

	// One request decides two things before any payload is spent.
	//
	// A host that does not answer at all is not worth forty more requests: on
	// a host that drops packets, that was the difference between one second
	// and over a minute per URL.
	//
	// And an endpoint that already answers with a destination is a redirector,
	// whatever its parameters are called, so every parameter on it is worth
	// attacking. The one carrying the destination need not have a recognizable
	// name or a url-shaped value: "?q=/" on a redirector is the case a name
	// list and a value test both miss.
	redirector, reachable := e.baseline(ctx, raw)
	if !reachable {
		slog.Debug("source did not answer, skipping its payloads", "url", raw)
		e.noteCoverage(false, false, 0, raw)

		return nil, nil
	}

	e.noteCoverage(true, redirector, len(targetParamsOn(parsed.Query(), redirector)), raw)

	hits, err := e.attackBlobs(ctx, raw)
	if err != nil {
		return nil, err
	}

	hits = append(hits, e.attackPollution(ctx, parsed)...)
	hits = append(hits, e.attackNestedRedirectURI(ctx, parsed)...)
	hits = append(hits, e.attackFetcherChain(ctx, parsed)...)

	// The payloads for one source run together. A pool over source URLs alone
	// leaves a single URL entirely serial, which is the common shape of a
	// targeted run and the case where --concurrency appeared to do nothing.
	// The client bounds what is actually on the wire, so fanning out here
	// cannot exceed the operator's limit.
	payloadHits, err := e.runPayloads(ctx, raw, parsed, redirector)

	hits = append(hits, payloadHits...)

	// A stopped source hands back what it proved, so the stages below are
	// skipped rather than the findings above being thrown away.
	if err != nil {
		return hits, err
	}

	// The chained class is what is left when the direct route is refused, so
	// it runs last and only where nothing else got through.
	hits = append(hits, e.attackChain(ctx, parsed, crackedParams(hits))...)

	return hits, nil
}

// crackedParams names the parameters a direct payload already walked through.
func crackedParams(hits []model.Finding) map[string]struct{} {
	out := map[string]struct{}{}

	for _, f := range hits {
		if f.Candidate.ParamName != "" {
			out[f.Candidate.ParamName] = struct{}{}
		}
	}

	return out
}

// runPayloads fires every payload at one source, concurrently.
func (e *Engine) runPayloads(
	ctx context.Context, raw string, parsed *url.URL, redirector bool,
) ([]model.Finding, error) {
	var (
		mu   sync.Mutex
		hits []model.Finding
		seen = map[string]struct{}{}
	)

	// claim reserves one param and payload combination, so two workers cannot
	// send the same request.
	claim := func(key string) bool {
		mu.Lock()
		defer mu.Unlock()

		if _, dup := seen[key]; dup {
			return false
		}

		seen[key] = struct{}{}

		return true
	}

	collect := func(found ...model.Finding) {
		if len(found) == 0 {
			return
		}

		mu.Lock()
		defer mu.Unlock()

		hits = append(hits, found...)
	}

	err := pool.Run(ctx, e.concurrency, e.payloads, func(ctx context.Context, p payload.Payload) error {
		switch p.Mechanism {
		case mechHeader:
			f, ok, err := e.probeHeader(ctx, raw, p)
			if err != nil {
				return err
			}

			if ok {
				collect(f)
			}
		case mechCRLF, mechPath:
			f, ok, err := e.probeCRLF(ctx, raw, p)
			if err != nil {
				return err
			}

			if ok {
				collect(f)
			}
		default:
			collect(e.attackParams(ctx, parsed, p, claim, redirector)...)
		}

		return nil
	})
	if err != nil && !stopped(err) {
		return nil, err
	}

	// A stable order, so two runs of the same scan report the same thing.
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].TechniqueID != hits[j].TechniqueID {
			return hits[i].TechniqueID < hits[j].TechniqueID
		}

		return hits[i].Payload < hits[j].Payload
	})

	return hits, err
}

func (e *Engine) attackKeyword(ctx context.Context, raw string) ([]model.Finding, error) {
	hits := []model.Finding{}

	for _, p := range e.payloads {
		if p.Mechanism == mechHeader {
			continue
		}

		expanded := payload.Expand(p, e.canary, hostOf(raw), "")
		altExpanded := payload.Expand(p, AltCanary(e.canary), hostOf(raw), "")
		probed := payload.Substitute(raw, e.keyword, expanded)
		altProbed := payload.Substitute(raw, e.keyword, altExpanded)

		f, ok, err := e.confirm(ctx, probe{
			source:    raw,
			probed:    probed,
			altProbed: altProbed,
			expanded:  expanded,
			payload:   p,
		})
		if err != nil {
			return nil, err
		}

		if ok {
			hits = append(hits, f)
		}
	}

	return hits, nil
}

func (e *Engine) attackParams(
	ctx context.Context, parsed *url.URL, p payload.Payload, claim func(string) bool, redirector bool,
) []model.Finding {
	hits := []model.Finding{}
	query := parsed.Query()

	for _, actual := range targetParamsOn(query, redirector) {
		// A bare-host payload belongs only on a host-shaped parameter, and a
		// full-URL payload only on the others.
		if isHostParam(actual) != (p.Mechanism == mechHost) {
			continue
		}

		current := query.Get(actual)

		// A value payload carries the parameter's current value verbatim, so
		// a value whose authority is internal would have detour ask the target
		// to reach it. There is nothing to carry.
		if payload.NeedsValue(p) && (current == "" || !safeValue(current, parsed.Hostname())) {
			continue
		}

		for _, trusted := range trustedHosts(parsed, current, e.trustedHosts) {
			expanded := payload.Expand(p, e.canary, trusted, current)

			if !claim(actual + "\x00" + expanded) {
				continue
			}

			altExpanded := payload.Expand(p, AltCanary(e.canary), trusted, current)

			f, ok, err := e.confirm(ctx, probe{
				source:    parsed.String(),
				probed:    withParam(parsed, actual, expanded),
				altProbed: withParam(parsed, actual, altExpanded),
				expanded:  expanded,
				payload:   p,
				param:     actual,
			})
			if err != nil || !ok {
				continue
			}

			hits = append(hits, f)

			// One trusted name getting through is the finding; the others
			// would only restate it.
			break
		}
	}

	return hits
}

func (e *Engine) probeHeader(ctx context.Context, raw string, p payload.Payload) (model.Finding, bool, error) {
	expanded := payload.Expand(p, e.canary, hostOf(raw), "")
	altExpanded := payload.Expand(p, AltCanary(e.canary), hostOf(raw), "")

	headers := forwardedHeaders(expanded)
	altHeaders := forwardedHeaders(altExpanded)

	return e.confirm(ctx, probe{
		source:    raw,
		probed:    raw,
		altProbed: raw,
		expanded:  expanded,
		payload:   p,
		extra:     headers,
		altExtra:  altHeaders,
	})
}

// forwardedHosts are the headers a reverse proxy or a framework will believe
// when it builds an absolute URL for a redirect. They are sent together
// because an application reads whichever one its stack happens to expose, and
// a probe that sends one at a time costs a request per header for no gain.
var forwardedHosts = []string{
	"X-Forwarded-Host",
	"X-Host",
	"X-Forwarded-Server",
	"X-HTTP-Host-Override",
	"X-Original-Host",
	"X-Original-URL",
	"X-Rewrite-URL",
	"Forwarded",
}

func forwardedHeaders(value string) http.Header {
	out := http.Header{}
	for _, name := range forwardedHosts {
		out.Set(name, value)
	}

	// Forwarded is the standardized one and takes a different shape.
	out.Set("Forwarded", "host="+value)

	return out
}

func (e *Engine) probeCRLF(ctx context.Context, raw string, p payload.Payload) (model.Finding, bool, error) {
	expanded := payload.Expand(p, e.canary, hostOf(raw), "")
	altExpanded := payload.Expand(p, AltCanary(e.canary), hostOf(raw), "")
	probed := joinPath(raw, expanded)
	altProbed := joinPath(raw, altExpanded)

	return e.confirm(ctx, probe{
		source:    raw,
		probed:    probed,
		altProbed: altProbed,
		expanded:  expanded,
		payload:   p,
	})
}

func (e *Engine) confirm(ctx context.Context, pr probe) (model.Finding, bool, error) {
	technique := pr.techniqueID()
	attempt := pr.attemptKey()

	// A completed attempt is not repeated, and a completed attempt that found
	// something hands the finding straight back. Skipping the work and the
	// result both is how a resumed run reported nothing at all.
	if e.checkpoint != nil && e.checkpoint.Seen(pr.source, attempt, technique) {
		recovered, ok := e.checkpoint.Recover(pr.source, attempt, technique)

		return recovered, ok, nil
	}

	pair, found, status, err := e.readDest(ctx, pr.probed, pr.extra, e.canary)
	if err != nil {
		return model.Finding{}, false, skipUnanswered(err)
	}

	hit := found.reached(pair, e.canary)
	if hit {
		altPair, altFound, _, err := e.readDest(ctx, pr.altProbed, pr.altExtra, AltCanary(e.canary))
		if err != nil {
			return model.Finding{}, false, skipUnanswered(err)
		}

		hit = altFound.reached(altPair, AltCanary(e.canary))
	}

	if !hit {
		if err := e.checkpoint.RecordAttempt(pr.source, attempt, technique, false); err != nil {
			return model.Finding{}, false, err
		}

		return model.Finding{}, false, nil
	}

	f := e.finding(pr, pair, found, status)

	if err := e.checkpoint.RecordHit(pr.source, attempt, technique, f); err != nil {
		return model.Finding{}, false, err
	}

	return f, true, nil
}

// skipUnanswered turns an unanswered probe into no verdict at all, and leaves
// every other error alone. The attempt is not recorded, so a later run makes
// it again.
func skipUnanswered(err error) error {
	if errors.Is(err, errUnanswered) {
		return nil
	}

	return err
}

// attemptKey identifies one attempt by the request it sends.
//
// The expanded payload does not identify it. One envelope that carries the
// destination in two fields yields two probes with the same source, the same
// expanded payload and the same technique, and keying on those three let the
// first one's miss suppress the second one's hit. The request is what differs,
// so the request is the key.
func (pr probe) attemptKey() string {
	if len(pr.extra) == 0 {
		return pr.probed
	}

	names := make([]string, 0, len(pr.extra))
	for name := range pr.extra {
		names = append(names, name)
	}

	sort.Strings(names)

	var b strings.Builder

	b.WriteString(pr.probed)

	for _, name := range names {
		b.WriteString("\x00")
		b.WriteString(name)
		b.WriteString(": ")
		b.WriteString(strings.Join(pr.extra.Values(name), ","))
	}

	return b.String()
}

// techniqueID prefers the envelope class the decoder identified over the
// payload's own id: a blob finding is an OR-B case whatever string got it in.
func (pr probe) techniqueID() string {
	if pr.blob != nil {
		return pr.blob.technique
	}

	return pr.payload.Technique
}

// reached reports whether this destination is the canary under any of the
// three readings: a parsed host, a host only a lenient parser sees, or a
// script-bearing scheme that has no host at all.
func (d dest) reached(pair resolve.Pair, canary string) bool {
	return d.url != "" && (d.quirk || d.scheme || resolve.HitsCanary(pair, canary))
}

// mechanism reports how the destination was carried.
func (pr probe) mechanism() string {
	if pr.blob != nil {
		return mechBlob
	}

	return pr.payload.Mechanism
}

// errUnanswered means a probe produced no usable answer.
//
// It is not a verdict. An attempt that was never answered is neither a hit
// nor a miss, and the difference matters: a miss is written to the checkpoint
// and never tried again, so recording one here made a cancelled or flaky
// probe a permanent "not vulnerable". An interrupted scan came back seven
// findings short and stayed short on every later resume.
var errUnanswered = errors.New("probe unanswered")

func (e *Engine) readDest(ctx context.Context, raw string, extra http.Header, canary string) (resolve.Pair, dest, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return resolve.Pair{}, dest{}, 0, fmt.Errorf("building request: %w", err)
	}

	for name, values := range extra {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}

	resp, err := e.client.Do(ctx, req)
	if err != nil {
		return resolve.Pair{}, dest{}, 0, errUnanswered
	}

	defer func() { _ = resp.Body.Close() }()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyScan))

	if pair, found, ok := pickCanaryDest(raw, destValues(resp, body), canary); ok {
		return pair, found, resp.StatusCode, nil
	}

	// A body that did not finish arriving cannot prove a destination is
	// absent. What it proves is that this attempt is worth making again.
	if readErr != nil {
		return resolve.Pair{}, dest{}, resp.StatusCode, errUnanswered
	}

	return resolve.Pair{}, dest{}, resp.StatusCode, nil
}

// destValues gathers every way this response could send a browser somewhere.
func destValues(resp *http.Response, body []byte) []dest {
	out := []dest{}

	for _, loc := range resp.Header.Values("Location") {
		out = append(out, dest{url: loc})
	}

	if u, ok := resolve.ParseRefresh(resp.Header.Get("Refresh")); ok {
		out = append(out, dest{url: u, mechanism: mechRefresh, technique: "OR-D06"})
	}

	// Every meta refresh, not just the first: a benign one may sit ahead of
	// the attacker-controlled one.
	if refreshed, ok := resolve.MetaRefresh(body); ok {
		for _, u := range refreshed {
			out = append(out, dest{url: u, mechanism: mechMeta, technique: "OR-C04"})
		}
	}

	return out
}

func pickCanaryDest(base string, dests []dest, canary string) (resolve.Pair, dest, bool) {
	for _, candidate := range dests {
		if candidate.url == "" {
			continue
		}

		pair, err := resolve.Interpret(base, candidate.url)
		if err != nil {
			continue
		}

		if resolve.HitsCanary(pair, canary) {
			return pair, candidate, true
		}
	}

	// A scheme other than http(s) has no host to match, and matching hosts is
	// all the resolver does. What proves these is that the scheme survived the
	// validator at all, with the canary still inside it.
	for _, candidate := range dests {
		if id, ok := schemeTechnique(candidate.url, canary); ok {
			candidate.technique = id
			candidate.mechanism = mechQuery
			candidate.scheme = true

			return resolve.Pair{}, candidate, true
		}
	}

	// Nothing parsed to the canary. A string net/url refuses can still carry
	// it, which is the whole Spring and delimiter-stuffing class.
	for _, candidate := range dests {
		if candidate.url == "" || !resolve.HitsCanaryQuirk(candidate.url, canary) {
			continue
		}

		candidate.quirk = true

		return resolve.Pair{}, candidate, true
	}

	return resolve.Pair{}, dest{}, false
}

// schemeTechniques name the schemes whose arrival at a sink is the finding.
// Ordered, not a map: a destination can match only one prefix, and a map would
// pick it at random between runs.
var schemeTechniques = []struct {
	prefix    string
	technique string
}{
	{"javascript:", "OR-E01"},
	{"vbscript:", "OR-E01"},
	{"data:", "OR-E02"},
}

// schemeTechnique reports whether a destination is a script-bearing scheme
// still carrying the canary.
func schemeTechnique(loc, canary string) (string, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(loc))
	if canary == "" || !strings.Contains(trimmed, strings.ToLower(canary)) {
		return "", false
	}

	for _, entry := range schemeTechniques {
		if strings.HasPrefix(trimmed, entry.prefix) {
			return entry.technique, true
		}
	}

	return "", false
}

func (e *Engine) finding(pr probe, pair resolve.Pair, found dest, status int) model.Finding {
	cand := model.NewNavigationCandidate(pr.source, pr.representation())
	cand.ParamName = pr.param

	if pr.blob != nil {
		cand.DecoderChain = pr.blob.chain
		cand.URLFields = pr.blob.fields
	}

	f := model.NewFinding()
	f.TechniqueID = pr.techniqueID()
	f.Mechanism = pr.mechanism()
	f.Payload = pr.expanded

	// How the response actually carried the destination outranks how the
	// payload was delivered.
	if found.technique != "" {
		f.TechniqueID = found.technique
		f.Mechanism = found.mechanism
	}

	// The parameter's role outranks both, where it defines one.
	if id, ok := techniqueForParam(pr.param); ok {
		f.TechniqueID = id
	}

	f.Candidate = cand

	f.Capabilities.RedirectExternal = !found.scheme
	f.Capabilities.InputControlled = true

	// A script-bearing scheme reaching the sink is script execution, not
	// navigation, so it earns its own capability and not the external-redirect
	// one.
	switch found.technique {
	case "OR-E01":
		f.Capabilities.JavaScriptScheme = true
	case "OR-E02":
		f.Capabilities.DataScheme = true
	}

	f.Capabilities.HopCount = 0
	f.Verdict = model.VerdictConfirmed

	if found.quirk || resolve.NeedsBrowserConfirm(pr.source, e.canary, pair) {
		f.Verdict = model.VerdictCandidate
	}

	f.Candidate.Capabilities = f.Capabilities
	f.Evidence = []string{
		fmt.Sprintf("status %d", status),
		destEvidence(found),
		"rfc_host=" + pair.RFC.Host,
		"browser_host=" + pair.Browser.Host,
	}

	if found.quirk {
		f.Evidence = append(f.Evidence,
			"quirk_hosts="+strings.Join(resolve.QuirkHosts(found.url), ","),
			"note=net/url refuses this authority; parsers disagree on the host",
		)
	}

	if pr.blob != nil {
		f.Evidence = append(f.Evidence,
			"blob_field="+string(pr.blob.field),
			"blob_strategy="+string(pr.blob.strategy),
		)
	}

	f.Repro = "curl -sI '" + strings.ReplaceAll(pr.probed, "'", `'\''`) + "'"
	f.ProbeURL = pr.probed

	return f
}

// destEvidence labels the evidence line with how the destination arrived.
func destEvidence(found dest) string {
	if found.mechanism == "" {
		return "Location: " + found.url
	}

	return found.mechanism + ": " + found.url
}

// representation names how the candidate carried the destination.
func (pr probe) representation() model.Representation {
	switch pr.mechanism() {
	case mechHeader:
		return model.RepresentationHeader
	case mechCRLF, mechPath:
		return model.RepresentationPathSegment
	case mechBlob:
		return model.RepresentationOpaqueBlob
	default:
		return model.RepresentationQueryParameter
	}
}

func joinPath(raw, suffix string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}

	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}

	path = strings.TrimSuffix(path, "/") + suffix
	parsed.RawPath = path

	decoded, decErr := url.PathUnescape(path)
	if decErr != nil {
		parsed.Path = path
	} else {
		parsed.Path = decoded
	}

	return parsed.String()
}

// trustedHost is the host a validator is likely to allow, used wherever a
// payload has to wear a trusted name to get past one.
//
// It refuses an internal address. The parameter's current value is the best
// guess at what the endpoint trusts, but detour then puts that host back into
// a payload, so a value already pointing at loopback or link-local would have
// detour ask the target to reach it. Aiming anything at an internal address is
// the operator's call on an authorized target and never a scanner's.
func trustedHost(parsed *url.URL, current string) string {
	if hosts := trustedHosts(parsed, current, nil); len(hosts) > 0 {
		return hosts[0]
	}

	return ""
}

// trustedHosts lists the hosts a validator might allow, best guess first.
//
// A payload that has to wear a trusted name is useless wearing the wrong one,
// and the right one is rarely in the parameter: a harvested URL says
// `?next=/account` or `?url=https://cdn.example/x`, essentially never the
// allowlisted host. Guessing a single candidate from the seed meant the entire
// allowlist-bypass family silently found nothing on real corpora, which is
// invisible precisely because a miss looks like a clean endpoint.
//
// So detour tries every host it has reason to believe: the one already in the
// parameter, the endpoint's own host, and anything the JS stage read out of a
// validator's allowlist.
func trustedHosts(parsed *url.URL, current string, extra []string) []string {
	origin := ""
	if parsed != nil {
		origin = parsed.Hostname()
	}

	out := make([]string, 0, len(extra)+2)
	seen := map[string]struct{}{}

	add := func(host string) {
		host = safeHost(host, origin)
		if host == "" {
			return
		}

		if _, dup := seen[strings.ToLower(host)]; dup {
			return
		}

		seen[strings.ToLower(host)] = struct{}{}

		out = append(out, host)
	}

	if current != "" {
		if u, err := url.Parse(current); err == nil {
			add(u.Hostname())
		}
	}

	add(origin)

	for _, host := range extra {
		add(host)
	}

	return out
}

func lookupQuery(q url.Values, name string) (string, bool) {
	if _, ok := q[name]; ok {
		return name, true
	}

	for k := range q {
		if strings.EqualFold(k, name) {
			return k, true
		}
	}

	return "", false
}

// hostOf is the source URL's own host, for the payload paths that have no
// parameter value to learn from. It refuses an internal host for the same
// reason trustedHost does.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}

	return u.Hostname()
}

func cloneURL(u *url.URL) *url.URL {
	cp := *u

	return &cp
}
