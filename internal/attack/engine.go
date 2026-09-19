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
	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/payload"
	"github.com/nedlir/detour/internal/pool"
	"github.com/nedlir/detour/internal/resolve"
)

const (
	mechHeader = "header"
	mechCRLF   = "crlf"
)

var redirectParams = []string{
	"url", "next", "redirect", "redirect_uri", "return", "returnurl", "return_to",
	"back", "backurl", "dest", "destination", "goto", "continue", "rurl", "redir",
	"uri", "target", "to", "out", "forward", "link", "callback", "relaystate",
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

	hits := []model.Finding{}
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

		expanded := payload.Expand(p, e.canary, hostOf(raw))
		altExpanded := payload.Expand(p, AltCanary(e.canary), hostOf(raw))
		probed := payload.Substitute(raw, e.keyword, expanded)
		altProbed := payload.Substitute(raw, e.keyword, altExpanded)

		f, ok, err := e.confirm(ctx, raw, probed, altProbed, expanded, p, "", nil, nil)
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

		trusted := trustedHost(parsed, query.Get(actual))
		expanded := payload.Expand(p, e.canary, trusted)

		key := actual + "\x00" + expanded
		if _, dup := seen[key]; dup {
			continue
		}

		seen[key] = struct{}{}
		next := cloneURL(parsed)
		q := next.Query()
		q.Set(actual, expanded)
		next.RawQuery = q.Encode()

		altExpanded := payload.Expand(p, AltCanary(e.canary), trusted)
		altNext := cloneURL(parsed)
		altQ := altNext.Query()
		altQ.Set(actual, altExpanded)
		altNext.RawQuery = altQ.Encode()

		f, ok, err := e.confirm(
			ctx,
			parsed.String(),
			next.String(),
			altNext.String(),
			expanded,
			p,
			actual,
			nil,
			nil,
		)
		if err != nil || !ok {
			continue
		}

		hits = append(hits, f)
	}

	return hits
}

func (e *Engine) probeHeader(ctx context.Context, raw string, p payload.Payload) (model.Finding, bool, error) {
	expanded := payload.Expand(p, e.canary, hostOf(raw))
	altExpanded := payload.Expand(p, AltCanary(e.canary), hostOf(raw))
	headers := http.Header{}
	headers.Set("X-Forwarded-Host", expanded)
	headers.Set("X-Host", expanded)

	altHeaders := http.Header{}
	altHeaders.Set("X-Forwarded-Host", altExpanded)
	altHeaders.Set("X-Host", altExpanded)

	return e.confirm(ctx, raw, raw, raw, expanded, p, "", headers, altHeaders)
}

func (e *Engine) probeCRLF(ctx context.Context, raw string, p payload.Payload) (model.Finding, bool, error) {
	expanded := payload.Expand(p, e.canary, hostOf(raw))
	altExpanded := payload.Expand(p, AltCanary(e.canary), hostOf(raw))
	probed := joinPath(raw, expanded)
	altProbed := joinPath(raw, altExpanded)

	return e.confirm(ctx, raw, probed, altProbed, expanded, p, "", nil, nil)
}

func (e *Engine) confirm(
	ctx context.Context,
	source, probed, altProbed, expanded string,
	p payload.Payload,
	param string,
	extra, altExtra http.Header,
) (model.Finding, bool, error) {
	if e.checkpoint != nil && e.checkpoint.Seen(source, expanded, p.Technique) {
		return model.Finding{}, false, nil
	}

	pair, dest, status, err := e.readDest(ctx, probed, extra, e.canary)
	if err != nil {
		return model.Finding{}, false, err
	}

	hit := dest != "" && resolve.HitsCanary(pair, e.canary)
	if hit {
		altPair, _, _, err := e.readDest(ctx, altProbed, altExtra, AltCanary(e.canary))
		if err != nil {
			return model.Finding{}, false, err
		}

		hit = resolve.HitsCanary(altPair, AltCanary(e.canary))
	}

	if err := e.checkpoint.RecordAttempt(source, expanded, p.Technique, hit); err != nil {
		return model.Finding{}, false, err
	}

	if !hit {
		return model.Finding{}, false, nil
	}

	return e.finding(source, probed, expanded, param, p, pair, dest, status), true, nil
}

func (e *Engine) readDest(ctx context.Context, raw string, extra http.Header, canary string) (resolve.Pair, string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return resolve.Pair{}, "", 0, fmt.Errorf("building request: %w", err)
	}

	for name, values := range extra {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}

	resp, err := e.client.Do(ctx, req)
	if err != nil {
		return resolve.Pair{}, "", 0, nil
	}

	defer func() { _ = resp.Body.Close() }()

	dests := destValues(resp)

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))

	if pair, dest, ok := pickCanaryDest(raw, dests, canary); ok {
		return pair, dest, resp.StatusCode, nil
	}

	return resolve.Pair{}, "", resp.StatusCode, nil
}

func destValues(resp *http.Response) []string {
	dests := append([]string{}, resp.Header.Values("Location")...)

	if raw, err := httputil.DumpResponse(resp, false); err == nil {
		dests = append(dests, resolve.LocationsFromRaw(raw)...)
	}

	if u, ok := resolve.ParseRefresh(resp.Header.Get("Refresh")); ok {
		dests = append(dests, u)
	}

	return dests
}

func pickCanaryDest(base string, dests []string, canary string) (resolve.Pair, string, bool) {
	for _, dest := range dests {
		if dest == "" {
			continue
		}

		pair, err := resolve.Interpret(base, dest)
		if err != nil {
			continue
		}

		if resolve.HitsCanary(pair, canary) {
			return pair, dest, true
		}
	}

	return resolve.Pair{}, "", false
}

func (e *Engine) finding(
	source, probed, expanded, param string,
	p payload.Payload,
	pair resolve.Pair,
	dest string,
	status int,
) model.Finding {
	rep := model.RepresentationQueryParameter

	switch {
	case extraIsHeader(p.Mechanism):
		rep = model.RepresentationHeader
	case p.Mechanism == mechCRLF:
		rep = model.RepresentationPathSegment
	}

	cand := model.NewNavigationCandidate(source, rep)
	cand.ParamName = param

	f := model.NewFinding()
	f.TechniqueID = p.Technique
	f.Mechanism = p.Mechanism
	f.Payload = expanded
	f.Candidate = cand
	f.Capabilities.RedirectExternal = true
	f.Capabilities.InputControlled = true
	f.Capabilities.HopCount = 0
	f.Verdict = model.VerdictConfirmed

	if resolve.NeedsBrowserConfirm(source, e.canary, pair) {
		f.Verdict = model.VerdictCandidate
	}

	f.Candidate.Capabilities = f.Capabilities
	f.Evidence = []string{
		fmt.Sprintf("status %d", status),
		"Location: " + dest,
		"rfc_host=" + pair.RFC.Host,
		"browser_host=" + pair.Browser.Host,
	}
	f.Repro = "curl -sI " + probed

	return f
}

func extraIsHeader(mechanism string) bool {
	return mechanism == mechHeader
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
