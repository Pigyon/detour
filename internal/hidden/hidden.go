// Package hidden brute-forces redirect parameter names against endpoints
// that harvesting left with no candidate at all.
//
// This is the expensive stage, which is why it is gated behind --deep. It
// only runs where the cheap signals found nothing, and a name is promoted
// only when the server does something with it.
package hidden

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// maxBodySample is how much of a response is read looking for a reflection.
const maxBodySample = 1 << 20

// Names are the parameter names worth guessing, ordered by how often they
// actually appear. The list is deliberately short: every name costs a request
// against every endpoint.
var Names = []string{
	"url", "next", "redirect", "redirect_uri", "redirectUrl", "return",
	"returnUrl", "return_to", "returnTo", "back", "backUrl", "back_url",
	"dest", "destination", "goto", "continue", "rurl", "redir", "r", "u",
	"uri", "target", "to", "out", "forward", "link", "callback", "go",
	"checkout_url", "image_url", "service", "ref", "site", "page", "path",
	"file", "view", "load", "window", "data", "domain", "host", "html",
	"login_url", "logout_url", "post_logout_redirect_uri", "RelayState",
}

// Doer issues a request.
//
// It must not follow redirects. The strong signal here is the Location header
// on the probe response, and a client that follows it reports a failure to
// reach the marker host instead.
type Doer interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

// Evidence says why a parameter name was promoted.
type Evidence string

const (
	// EvidenceRedirect means the server sent the probe value in a Location.
	// This is the strong signal.
	EvidenceRedirect Evidence = "redirect"
	// EvidenceReflected means the probe value came back in the body. Weaker,
	// but it proves the parameter is read.
	EvidenceReflected Evidence = "reflected"
)

// Hit is one promoted parameter name.
type Hit struct {
	URL      string   `json:"url"`
	Param    string   `json:"param"`
	Evidence Evidence `json:"evidence"`
	// Probe is the URL that demonstrated it.
	Probe string `json:"probe"`
}

// Options configures discovery.
type Options struct {
	// Marker is the sentinel value probed with. It has to be distinctive
	// enough that finding it in a body means something.
	Marker string
	// Names overrides the built-in name list.
	Names []string
	// Concurrency bounds in-flight probes.
	Concurrency int
}

const (
	defaultMarker      = "https://detour-probe.invalid/x"
	defaultConcurrency = 8
)

// Finder probes endpoints for unlinked redirect parameters.
type Finder struct {
	client Doer
	opts   Options
}

// New builds a finder.
func New(client Doer, opts Options) *Finder {
	if opts.Marker == "" {
		opts.Marker = defaultMarker
	}

	if len(opts.Names) == 0 {
		opts.Names = Names
	}

	if opts.Concurrency <= 0 {
		opts.Concurrency = defaultConcurrency
	}

	return &Finder{client: client, opts: opts}
}

// Discover probes every name against target and returns the ones the server
// reacted to.
func (f *Finder) Discover(ctx context.Context, target string) ([]Hit, error) {
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parsing target: %w", err)
	}

	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		hits = []Hit{}
		sem  = make(chan struct{}, f.opts.Concurrency)
	)

	for _, name := range f.opts.Names {
		// A parameter the endpoint already carries is not hidden.
		if parsed.Query().Has(name) {
			continue
		}

		wg.Add(1)

		go func(name string) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			hit, found := f.probe(ctx, parsed, name)
			if !found {
				return
			}

			mu.Lock()

			hits = append(hits, hit)
			mu.Unlock()
		}(name)
	}

	wg.Wait()

	return hits, nil
}

func (f *Finder) probe(ctx context.Context, base *url.URL, name string) (Hit, bool) {
	probe := withParam(base, name, f.opts.Marker)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probe, nil)
	if err != nil {
		return Hit{}, false
	}

	resp, err := f.client.Do(ctx, req)
	if err != nil {
		return Hit{}, false
	}

	defer func() { _ = resp.Body.Close() }()

	if location := resp.Header.Get("Location"); strings.Contains(location, markerHost(f.opts.Marker)) {
		return Hit{URL: base.String(), Param: name, Evidence: EvidenceRedirect, Probe: probe}, true
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySample))
	if err != nil {
		return Hit{}, false
	}

	if strings.Contains(string(body), markerHost(f.opts.Marker)) {
		return Hit{URL: base.String(), Param: name, Evidence: EvidenceReflected, Probe: probe}, true
	}

	return Hit{}, false
}

// markerHost reduces the marker to the part that must appear verbatim. A
// server that re-encodes the value still leaves the host intact.
func markerHost(marker string) string {
	parsed, err := url.Parse(marker)
	if err != nil || parsed.Hostname() == "" {
		return marker
	}

	return parsed.Hostname()
}

func withParam(base *url.URL, name, value string) string {
	next := *base
	query := next.Query()
	query.Set(name, value)
	next.RawQuery = query.Encode()

	return next.String()
}

// Promote turns hits into URLs carrying the discovered parameter, ready for
// the attack engine.
func Promote(hits []Hit) []string {
	out := make([]string, 0, len(hits))
	for _, hit := range hits {
		out = append(out, hit.Probe)
	}

	return out
}
