package js

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
)

// HostResolver answers whether a hostname resolves. It is declared here
// because this is where it is consumed, and *net.Resolver satisfies it as is.
type HostResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// DanglingHosts returns the allowlisted hosts that do not resolve. An
// allowlist entry pointing at an unregistered domain is a takeover: whoever
// claims it inherits the trust of every guard that lists it.
//
// Only a definitive not-found counts. A timeout or a refused server is a
// failure to answer, and reporting it as dangling would be a false positive.
func DanglingHosts(ctx context.Context, r HostResolver, hosts []string) []string {
	if r == nil {
		r = net.DefaultResolver
	}

	out := []string{}
	seen := map[string]struct{}{}

	for _, raw := range hosts {
		host := hostOf(raw)
		if host == "" {
			continue
		}

		if _, dup := seen[host]; dup {
			continue
		}

		seen[host] = struct{}{}

		if _, err := r.LookupHost(ctx, host); err != nil && isNotFound(err) {
			out = append(out, host)
		}
	}

	sort.Strings(out)

	return out
}

// isNotFound distinguishes "this name does not exist" from "the lookup did not
// finish".
func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}

	return false
}

// hostOf reduces an allowlist entry to a bare hostname, since entries are
// written as hosts, origins, and occasionally full URLs.
func hostOf(raw string) string {
	host := strings.TrimSpace(raw)
	host = strings.TrimPrefix(host, "*.")

	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}

	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}

	if at := strings.LastIndex(host, "@"); at >= 0 {
		host = host[at+1:]
	}

	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	host = strings.Trim(strings.ToLower(host), ".")
	if host == "" || strings.ContainsAny(host, " \t") {
		return ""
	}

	return host
}

// DanglingVerdicts turns unresolvable allowlist entries into findings.
func DanglingVerdicts(hosts []string) []Verdict {
	out := make([]Verdict, 0, len(hosts))

	for _, host := range hosts {
		out = append(out, Verdict{
			TechniqueID: "OR-F08",
			Severity:    SeverityCandidate,
			Sink:        "allowlist",
			Discrepancy: "allowlisted host " + host + " does not resolve, so registering it inherits the guard's trust",
			Payload:     "https://" + host + "/",
			Evidence:    []string{"allowlist entry " + host, "dns NXDOMAIN"},
		})
	}

	return out
}
