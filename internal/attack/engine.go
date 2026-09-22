// Package attack fires templated payloads at navigation candidates and scores hits.
package attack

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
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
	mechHeader  = "header"
	mechCRLF    = "crlf"
	mechBlob    = "blob"
	mechQuery   = "query"
	mechMeta    = "meta"
	mechRefresh = "refresh"

	// maxBodyScan is how much of a response body is read looking for a meta
	// refresh. The tag lives in the head, so this is generous.
	maxBodyScan = 1 << 20
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
}

// redirectParams is the canonical list, shared with the classifier so the
// engine never skips a parameter selection just flagged as interesting.
var redirectParams = corpus.RedirectParams()

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

// Engine probes candidates with the built-in payload set.
type Engine struct {
	client      *client.Client
	canary      string
	keyword     string
	payloads    []payload.Payload
	concurrency int
	checkpoint  *checkpoint.Store
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

// SetCheckpoint records attempts so --resume can skip completed work.
func (e *Engine) SetCheckpoint(store *checkpoint.Store) {
	e.checkpoint = store
}

// AltCanary is the independent second host used for the input_controlled check.
func AltCanary(canary string) string {
	host, rest, ok := strings.Cut(canary, ".")
	if ok {
		return host + "2." + rest
	}

	return canary + "2"
}

// Run attacks every source URL and returns capability-scored findings.
func (e *Engine) Run(ctx context.Context, sources []string) ([]model.Finding, error) {
	var (
		mu       sync.Mutex
		findings = []model.Finding{}
	)

	err := pool.Run(ctx, e.concurrency, sources, func(ctx context.Context, raw string) error {
		hits, err := e.attackOne(ctx, raw)
		if err != nil {
			return err
		}

		if len(hits) == 0 {
			return nil
		}

		mu.Lock()

		findings = append(findings, hits...)
		mu.Unlock()

		return nil
	})
	if err != nil {
		return nil, err
	}

	return findings, nil
}

func (e *Engine) attackOne(ctx context.Context, raw string) ([]model.Finding, error) {
	if payload.HasKeyword(raw, e.keyword) {
		return e.attackKeyword(ctx, raw)
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing source: %w", err)
	}

	hits, err := e.attackBlobs(ctx, raw)
	if err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}

	for _, p := range e.payloads {
		switch p.Mechanism {
		case mechHeader:
			f, ok, err := e.probeHeader(ctx, raw, p)
			if err != nil {
				return nil, err
			}

			if ok {
				hits = append(hits, f)
			}
		case mechCRLF:
			f, ok, err := e.probeCRLF(ctx, raw, p)
			if err != nil {
				return nil, err
			}

			if ok {
				hits = append(hits, f)
			}
		default:
			hits = append(hits, e.attackParams(ctx, parsed, p, seen)...)
		}
	}

	return hits, nil
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

func (e *Engine) attackParams(ctx context.Context, parsed *url.URL, p payload.Payload, seen map[string]struct{}) []model.Finding {
	hits := []model.Finding{}
	query := parsed.Query()

	for _, name := range redirectParams {
		actual, ok := lookupQuery(query, name)
		if !ok {
			continue
		}

		current := query.Get(actual)
		if payload.NeedsValue(p) && current == "" {
			continue
		}

		trusted := trustedHost(parsed, current)
		expanded := payload.Expand(p, e.canary, trusted, current)

		key := actual + "\x00" + expanded
		if _, dup := seen[key]; dup {
			continue
		}

		seen[key] = struct{}{}
		next := cloneURL(parsed)
		q := next.Query()
		q.Set(actual, expanded)
		next.RawQuery = q.Encode()

		altExpanded := payload.Expand(p, AltCanary(e.canary), trusted, current)
		altNext := cloneURL(parsed)
		altQ := altNext.Query()
		altQ.Set(actual, altExpanded)
		altNext.RawQuery = altQ.Encode()

		f, ok, err := e.confirm(ctx, probe{
			source:    parsed.String(),
			probed:    next.String(),
			altProbed: altNext.String(),
			expanded:  expanded,
			payload:   p,
			param:     actual,
		})
		if err != nil || !ok {
			continue
		}

		hits = append(hits, f)
	}

	return hits
}

func (e *Engine) probeHeader(ctx context.Context, raw string, p payload.Payload) (model.Finding, bool, error) {
	expanded := payload.Expand(p, e.canary, hostOf(raw), "")
	altExpanded := payload.Expand(p, AltCanary(e.canary), hostOf(raw), "")
	headers := http.Header{}
	headers.Set("X-Forwarded-Host", expanded)
	headers.Set("X-Host", expanded)

	altHeaders := http.Header{}
	altHeaders.Set("X-Forwarded-Host", altExpanded)
	altHeaders.Set("X-Host", altExpanded)

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

	if e.checkpoint != nil && e.checkpoint.Seen(pr.source, pr.expanded, technique) {
		return model.Finding{}, false, nil
	}

	pair, found, status, err := e.readDest(ctx, pr.probed, pr.extra, e.canary)
	if err != nil {
		return model.Finding{}, false, err
	}

	hit := found.url != "" && resolve.HitsCanary(pair, e.canary)
	if hit {
		altPair, _, _, err := e.readDest(ctx, pr.altProbed, pr.altExtra, AltCanary(e.canary))
		if err != nil {
			return model.Finding{}, false, err
		}

		hit = resolve.HitsCanary(altPair, AltCanary(e.canary))
	}

	if err := e.checkpoint.RecordAttempt(pr.source, pr.expanded, technique, hit); err != nil {
		return model.Finding{}, false, err
	}

	if !hit {
		return model.Finding{}, false, nil
	}

	return e.finding(pr, pair, found, status), true, nil
}

// techniqueID prefers the envelope class the decoder identified over the
// payload's own id: a blob finding is an OR-B case whatever string got it in.
func (pr probe) techniqueID() string {
	if pr.blob != nil {
		return pr.blob.technique
	}

	return pr.payload.Technique
}

// mechanism reports how the destination was carried.
func (pr probe) mechanism() string {
	if pr.blob != nil {
		return mechBlob
	}

	return pr.payload.Mechanism
}

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
		return resolve.Pair{}, dest{}, 0, nil
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyScan))

	if pair, found, ok := pickCanaryDest(raw, destValues(resp, body), canary); ok {
		return pair, found, resp.StatusCode, nil
	}

	return resolve.Pair{}, dest{}, resp.StatusCode, nil
}

// destValues gathers every way this response could send a browser somewhere.
func destValues(resp *http.Response, body []byte) []dest {
	out := []dest{}

	for _, loc := range resp.Header.Values("Location") {
		out = append(out, dest{url: loc})
	}

	// Raw bytes catch a second Location smuggled in by CRLF injection, which
	// net/http folds away.
	if raw, err := httputil.DumpResponse(resp, false); err == nil {
		for _, loc := range resolve.LocationsFromRaw(raw) {
			out = append(out, dest{url: loc})
		}
	}

	if u, ok := resolve.ParseRefresh(resp.Header.Get("Refresh")); ok {
		out = append(out, dest{url: u, mechanism: mechRefresh, technique: "OR-D06"})
	}

	if u, ok := resolve.MetaRefresh(body); ok {
		out = append(out, dest{url: u, mechanism: mechMeta, technique: "OR-C04"})
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

	return resolve.Pair{}, dest{}, false
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

	f.Candidate = cand
	f.Capabilities.RedirectExternal = true
	f.Capabilities.InputControlled = true
	f.Capabilities.HopCount = 0
	f.Verdict = model.VerdictConfirmed

	if resolve.NeedsBrowserConfirm(pr.source, e.canary, pair) {
		f.Verdict = model.VerdictCandidate
	}

	f.Candidate.Capabilities = f.Capabilities
	f.Evidence = []string{
		fmt.Sprintf("status %d", status),
		destEvidence(found),
		"rfc_host=" + pair.RFC.Host,
		"browser_host=" + pair.Browser.Host,
	}

	if pr.blob != nil {
		f.Evidence = append(f.Evidence,
			"blob_field="+string(pr.blob.field),
			"blob_strategy="+string(pr.blob.strategy),
		)
	}

	f.Repro = "curl -sI " + pr.probed
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
	case mechCRLF:
		return model.RepresentationPathSegment
	case mechBlob:
		return model.RepresentationOpaqueBlob
	case mechMeta, mechRefresh:
		return model.RepresentationQueryParameter
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

func trustedHost(parsed *url.URL, current string) string {
	if current != "" {
		if u, err := url.Parse(current); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}

	if parsed != nil {
		return parsed.Hostname()
	}

	return ""
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

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}

	return u.Hostname()
}

func cloneURL(u *url.URL) *url.URL {
	cp := *u
	if u.RawQuery != "" {
		cp.RawQuery = u.RawQuery
	}

	return &cp
}
