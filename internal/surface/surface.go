// Package surface maps a target's attack surface: which hosts exist, what
// they resolve to, and what answers on them.
//
// The part that matters for open redirects is the CNAME. A customer subdomain
// delegated to an email or marketing platform runs that vendor's click
// wrapper on the customer's own domain, with the customer's certificate, and
// every allowlist in the organization trusts it.
package surface

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/nedlir/detour/internal/corpus"

	"github.com/nedlir/detour/internal/pool"
)

// Host is one discovered host and what probing learned about it.
type Host struct {
	Host  string   `json:"host"`
	IPs   []string `json:"ips,omitempty"`
	CNAME string   `json:"cname,omitempty"`
	// Vendor names the platform the CNAME points at, when it is one detour
	// knows. A non-empty value here is a priority target.
	Vendor string `json:"vendor,omitempty"`
	// URL is the origin that answered, empty when nothing did.
	URL    string   `json:"url,omitempty"`
	Status int      `json:"status,omitempty"`
	Title  string   `json:"title,omitempty"`
	Tech   []string `json:"tech,omitempty"`
}

// Live reports whether anything answered on this host.
func (h Host) Live() bool {
	return h.Status > 0
}

// Priority reports whether this host deserves attention before the others.
func (h Host) Priority() bool {
	return h.Vendor != ""
}

// Result is a whole surface run.
type Result struct {
	Domain string   `json:"domain"`
	Hosts  []Host   `json:"hosts"`
	Errors []string `json:"errors,omitempty"`
}

// Priority returns the vendor-delegated hosts, which is the list a hunter
// should look at first.
func (r Result) Priority() []Host {
	out := []Host{}

	for _, h := range r.Hosts {
		if h.Priority() {
			out = append(out, h)
		}
	}

	return out
}

// Origins returns the live origins, ready to seed a harvest.
func (r Result) Origins() []string {
	out := []string{}

	for _, h := range r.Hosts {
		if h.URL != "" {
			out = append(out, h.URL)
		}
	}

	sort.Strings(out)

	return out
}

// Enumerator finds subdomains of a domain.
type Enumerator interface {
	Enumerate(ctx context.Context, domain string) ([]string, error)
}

// Resolver fills in DNS facts for a host.
type Resolver interface {
	Resolve(ctx context.Context, host string) (ips []string, cname string, err error)
}

// Prober asks what answers on a host.
type Prober interface {
	Probe(ctx context.Context, host string) (Host, error)
}

// Options configures a surface run.
type Options struct {
	Enumerator Enumerator
	Resolver   Resolver
	Prober     Prober
	// Concurrency bounds resolve and probe work.
	Concurrency int
	// Allow decides which discovered hosts may be resolved and probed.
	//
	// Enumeration returns whatever the sources hold, which for a large
	// organization routinely includes hosts outside the engagement. Every
	// other stage passes through the scope guard before it sends anything;
	// this one has to as well, or a run resolves and requests names the
	// operator was never cleared for. A nil Allow permits everything, which is
	// only correct for a test.
	Allow func(host string) bool
}

const defaultConcurrency = 20

// Mapper runs the three stages. Each is an interface so a run can skip one,
// and so tests need no network.
type Mapper struct {
	opts Options
}

// New builds a mapper.
func New(opts Options) *Mapper {
	if opts.Concurrency <= 0 {
		opts.Concurrency = defaultConcurrency
	}

	return &Mapper{opts: opts}
}

// Run enumerates, resolves, and probes a domain.
func (m *Mapper) Run(ctx context.Context, domain string) Result {
	result := Result{Domain: domain, Hosts: []Host{}, Errors: []string{}}

	hosts := []string{domain}

	if m.opts.Enumerator != nil {
		found, err := m.opts.Enumerator.Enumerate(ctx, domain)
		if err != nil {
			result.Errors = append(result.Errors, "enumerate: "+err.Error())
		}

		hosts = append(hosts, found...)
	}

	inScope, refused := m.partition(dedupeHosts(hosts))
	if refused > 0 {
		result.Errors = append(result.Errors,
			fmt.Sprintf("surface: %d discovered hosts were out of scope and not contacted", refused))
	}

	result.Hosts = m.inspect(ctx, inScope, &result)

	sort.Slice(result.Hosts, func(i, j int) bool {
		if result.Hosts[i].Priority() != result.Hosts[j].Priority() {
			return result.Hosts[i].Priority()
		}

		return result.Hosts[i].Host < result.Hosts[j].Host
	})

	return result
}

// partition keeps the discovered hosts the scope guard allows.
func (m *Mapper) partition(hosts []string) (allowed []string, refused int) {
	if m.opts.Allow == nil {
		return hosts, 0
	}

	allowed = make([]string, 0, len(hosts))

	for _, host := range hosts {
		if m.opts.Allow(host) {
			allowed = append(allowed, host)

			continue
		}

		refused++
	}

	return allowed, refused
}

// inspect resolves and probes every host, bounded by Concurrency.
//
// The bound is on goroutines, not just on work in flight. Spawning one per
// host and having each wait on a semaphore costs a goroutine stack per host,
// which on a large organization's subdomain list is hundreds of thousands of
// them and gigabytes of stacks, for a list subfinder returns routinely.
func (m *Mapper) inspect(ctx context.Context, hosts []string, result *Result) []Host {
	var (
		mu   sync.Mutex
		out  = make([]Host, 0, len(hosts))
		errs []string
	)

	_ = pool.Run(ctx, m.opts.Concurrency, hosts, func(ctx context.Context, host string) error {
		entry, failures := m.inspectOne(ctx, host)

		mu.Lock()
		defer mu.Unlock()

		out = append(out, entry)
		errs = append(errs, failures...)

		return nil
	})

	result.Errors = append(result.Errors, errs...)

	return out
}

func (m *Mapper) inspectOne(ctx context.Context, host string) (Host, []string) {
	entry := Host{Host: host}
	errs := []string{}

	if m.opts.Resolver != nil {
		ips, cname, err := m.opts.Resolver.Resolve(ctx, host)
		if err != nil {
			errs = append(errs, "resolve "+host+": "+err.Error())
		}

		entry.IPs = ips
		entry.CNAME = cname

		if vendor, ok := corpus.MatchCNAME(cname); ok {
			entry.Vendor = vendor
		}
	}

	if m.opts.Prober == nil {
		return entry, errs
	}

	probed, err := m.opts.Prober.Probe(ctx, host)
	if err != nil {
		errs = append(errs, "probe "+host+": "+err.Error())

		return entry, errs
	}

	entry.URL = probed.URL
	entry.Status = probed.Status
	entry.Title = probed.Title
	entry.Tech = probed.Tech

	return entry, errs
}

func dedupeHosts(hosts []string) []string {
	seen := map[string]struct{}{}
	out := []string{}

	for _, host := range hosts {
		normalized := strings.Trim(strings.ToLower(strings.TrimSpace(host)), ".")
		if normalized == "" {
			continue
		}

		if _, dup := seen[normalized]; dup {
			continue
		}

		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}

	sort.Strings(out)

	return out
}
