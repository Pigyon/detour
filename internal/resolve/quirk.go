package resolve

import (
	"slices"
	"strings"
)

// Some authority strings are rejected outright by net/url and still navigate
// somewhere in a real client. `https://allowed.example[@attacker.example/` is
// the Spring class (CVE-2024-22243 and its siblings): the framework's userinfo
// regex stops at `[`, so it extracts a host the HTTP client never uses.
// `https://allowed.example:443:\@@attacker.example/` is the same idea with
// delimiter stuffing instead of a bracket.
//
// Dropping these is how a scanner reports such an endpoint clean. detour
// instead extracts every host a lenient parser could land on and reports the
// result at candidate tier, because a same-origin server-side check genuinely
// cannot settle which one a browser picks. That is what the browser stage is
// for.

// maxQuirkHosts bounds the extraction so a pathological authority cannot turn
// one response into unbounded work.
const maxQuirkHosts = 8

// QuirkHosts returns the hosts a lenient parser could extract from an
// authority that net/url refuses, canonicalized and deduplicated.
//
// It returns nothing for a string net/url accepts: there is no disagreement to
// report, and the ordinary interpretations already cover it.
func QuirkHosts(loc string) []string {
	authority, ok := authorityOf(loc)
	if !ok {
		return nil
	}

	out := make([]string, 0, maxQuirkHosts)
	seen := map[string]struct{}{}

	add := func(candidate string) {
		host := CanonicalHost(trimHostPort(candidate))
		if host == "" || len(out) >= maxQuirkHosts {
			return
		}

		if _, dup := seen[host]; dup {
			return
		}

		seen[host] = struct{}{}
		out = append(out, host)
	}

	// A bracket terminates the userinfo for Spring and nothing else, so what
	// sits in front of it is a host one side of the disagreement will use.
	if before, _, found := strings.Cut(authority, "[@"); found {
		add(before)
	}

	// Every `@`-delimited segment is a host under some parser. The last one is
	// what RFC 3986 would pick; the earlier ones are what the stuffed-delimiter
	// payloads are aiming at.
	segments := strings.Split(authority, "@")
	for _, segment := range slices.Backward(segments) {
		add(segment)
	}

	return out
}

// authorityOf returns the authority component of an absolute URL, but only
// when net/url cannot parse the string. A parseable URL has no quirk to
// report.
func authorityOf(loc string) (string, bool) {
	_, authority, found := strings.Cut(loc, "://")
	if !found {
		return "", false
	}

	if _, err := RFC3986("", loc); err == nil {
		return "", false
	}

	if cut := strings.IndexAny(authority, "/?#"); cut >= 0 {
		authority = authority[:cut]
	}

	if authority == "" {
		return "", false
	}

	return authority, true
}

// trimHostPort strips a trailing port and any leading delimiter debris, so
// `allowed.example:443:\` reduces to `allowed.example`.
func trimHostPort(s string) string {
	s = strings.TrimLeft(s, "\\/ \t")

	if cut := strings.IndexAny(s, ":[]\\ "); cut >= 0 {
		s = s[:cut]
	}

	return strings.TrimSpace(s)
}

// HitsCanaryQuirk reports whether a lenient reading of loc lands on the canary
// while net/url refuses the string entirely.
func HitsCanaryQuirk(loc, canary string) bool {
	want := CanonicalHost(canary)
	if want == "" {
		return false
	}

	return slices.ContainsFunc(QuirkHosts(loc), func(host string) bool {
		return HostSuffix(host, want)
	})
}
