package surface

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	dnsxlib "github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/retryablehttp-go"
	subfinder "github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

const (
	// enumTimeoutSeconds bounds each subfinder source.
	enumTimeoutSeconds = 20
	// enumMaxMinutes bounds the whole enumeration.
	enumMaxMinutes = 5
	// probeTimeout bounds one HTTP probe.
	probeTimeout = 10 * time.Second
)

// Subfinder enumerates subdomains passively.
type Subfinder struct {
	threads int
}

// NewSubfinder builds the enumerator.
func NewSubfinder(threads int) *Subfinder {
	if threads <= 0 {
		threads = 10
	}

	return &Subfinder{threads: threads}
}

// Enumerate returns the subdomains subfinder found. Sources needing keys are
// simply absent when none are configured, which is the intended keyless path.
func (s *Subfinder) Enumerate(ctx context.Context, domain string) ([]string, error) {
	options := &subfinder.Options{
		Threads:            s.threads,
		Timeout:            enumTimeoutSeconds,
		MaxEnumerationTime: enumMaxMinutes,
		Silent:             true,
	}

	runner, err := subfinder.NewRunner(options)
	if err != nil {
		return nil, fmt.Errorf("building subfinder: %w", err)
	}

	found, err := runner.EnumerateSingleDomainWithCtx(ctx, domain, nil)
	if err != nil {
		return nil, fmt.Errorf("enumerating %s: %w", domain, err)
	}

	out := make([]string, 0, len(found))
	for host := range found {
		out = append(out, host)
	}

	sort.Strings(out)

	return out, nil
}

// DNSResolver resolves hosts and, importantly, reports the CNAME.
type DNSResolver struct {
	client *dnsxlib.DNSX
}

// NewDNSResolver builds the resolver.
func NewDNSResolver() (*DNSResolver, error) {
	options := dnsxlib.DefaultOptions
	options.QuestionTypes = append(options.QuestionTypes, dnsTypeCNAME)

	client, err := dnsxlib.New(options)
	if err != nil {
		return nil, fmt.Errorf("building resolver: %w", err)
	}

	return &DNSResolver{client: client}, nil
}

// dnsTypeCNAME is the CNAME question type, spelled out so the import of a DNS
// library is not needed just for a constant.
const dnsTypeCNAME = 5

// Resolve returns a host's addresses and its CNAME target.
func (r *DNSResolver) Resolve(_ context.Context, host string) ([]string, string, error) {
	data, err := r.client.QueryOne(host)
	if err != nil {
		return nil, "", fmt.Errorf("resolving %s: %w", host, err)
	}

	if data == nil {
		return nil, "", nil
	}

	cname := ""
	if len(data.CNAME) > 0 {
		cname = data.CNAME[0]
	}

	return data.A, cname, nil
}

// HTTPProber probes a host over https then http, recording what answered.
type HTTPProber struct {
	client *httpx.HTTPX
}

// NewHTTPProber builds the prober.
func NewHTTPProber() (*HTTPProber, error) {
	options := httpx.DefaultOptions
	options.Timeout = probeTimeout
	options.FollowRedirects = false

	client, err := httpx.New(&options)
	if err != nil {
		return nil, fmt.Errorf("building prober: %w", err)
	}

	return &HTTPProber{client: client}, nil
}

// Probe tries https first, then http. A host that answers on neither comes
// back with a zero status rather than an error: not answering is a fact, not
// a failure.
func (p *HTTPProber) Probe(ctx context.Context, host string) (Host, error) {
	for _, scheme := range []string{"https", "http"} {
		entry, err := p.probeOne(ctx, scheme+"://"+host)
		if err != nil {
			continue
		}

		return entry, nil
	}

	// Neither scheme answered. That is a fact about the host, not a failure of
	// the probe, so it comes back as a host with no status rather than an
	// error that would abort the surface run.
	return Host{Host: host}, nil
}

func (p *HTTPProber) probeOne(ctx context.Context, target string) (Host, error) {
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Host{}, fmt.Errorf("building probe request: %w", err)
	}

	resp, err := p.client.Do(req, httpx.UnsafeOptions{})
	if err != nil {
		return Host{}, fmt.Errorf("probing %s: %w", target, err)
	}

	return Host{
		URL:    target,
		Status: resp.StatusCode,
		Title:  httpx.ExtractTitle(resp),
		Tech:   techFrom(resp),
	}, nil
}

// techHeaders are the response headers that name a technology outright. This
// is deliberately modest: detour needs enough to recognize a vendor stack,
// not a full fingerprinting engine.
var techHeaders = []string{
	"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator",
	"X-Drupal-Cache", "X-Shopify-Stage", "X-Varnish", "Via",
}

func techFrom(resp *httpx.Response) []string {
	if resp == nil {
		return nil
	}

	seen := map[string]struct{}{}
	out := []string{}

	for _, name := range techHeaders {
		for _, value := range resp.Headers[name] {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}

			if _, dup := seen[value]; dup {
				continue
			}

			seen[value] = struct{}{}
			out = append(out, value)
		}
	}

	sort.Strings(out)

	return out
}
