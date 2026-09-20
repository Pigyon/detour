// Package dork generates redirect-shaped search queries for a target.
//
// Generation is entirely offline. Nothing here contacts a search engine, so
// it costs nothing, needs no key, and can be pasted anywhere. Running the
// queries against an API is a separate, keyed concern.
package dork

import (
	"sort"
	"strings"
)

// Engine names a search syntax.
type Engine string

const (
	// Google is also close enough for Bing and DuckDuckGo.
	Google Engine = "google"
	// GitHub searches code rather than the web, which finds the parameter
	// names an organization's own source uses.
	GitHub Engine = "github"
)

// Query is one generated search.
type Query struct {
	Engine Engine `json:"engine"`
	Query  string `json:"query"`
	// Why says what the query is looking for, so a list of fifty is readable.
	Why string `json:"why"`
}

// paramNames are the redirect-shaped parameters worth a dork. Kept shorter
// than the engine's full list on purpose: a dork list nobody reads is worse
// than a short one somebody runs.
var paramNames = []string{
	"redirect", "redirect_uri", "url", "next", "return", "returnUrl",
	"return_to", "back", "backUrl", "dest", "destination", "goto",
	"continue", "r", "u", "target", "link", "out", "forward",
	"callback", "RelayState", "post_logout_redirect_uri",
}

// vendorPaths are click-wrapper formats. Finding one of these on a target's
// own domain is the highest value result in the list.
var vendorPaths = []string{
	"/track/click2/",
	"/ls/click",
	"/api/v3/click",
	"/a/click",
	"/r/?id=",
}

// Generate builds the query set for a domain.
func Generate(domain string) []Query {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return []Query{}
	}

	out := []Query{}
	out = append(out, paramQueries(domain)...)
	out = append(out, vendorQueries(domain)...)
	out = append(out, shapeQueries(domain)...)
	out = append(out, codeQueries(domain)...)

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Engine != out[j].Engine {
			return out[i].Engine < out[j].Engine
		}

		return out[i].Query < out[j].Query
	})

	return out
}

// paramQueries look for a redirect-shaped parameter in an indexed URL.
func paramQueries(domain string) []Query {
	out := make([]Query, 0, len(paramNames))

	for _, name := range paramNames {
		out = append(out, Query{
			Engine: Google,
			Query:  "site:" + domain + " inurl:" + name + "=",
			Why:    "indexed URL carrying a " + name + " parameter",
		})
	}

	return out
}

// vendorQueries look for an email or marketing click wrapper served from the
// target's own domain.
func vendorQueries(domain string) []Query {
	out := make([]Query, 0, len(vendorPaths))

	for _, path := range vendorPaths {
		out = append(out, Query{
			Engine: Google,
			Query:  "site:" + domain + " inurl:\"" + path + "\"",
			Why:    "click wrapper " + path + " on a first-party host",
		})
	}

	return out
}

// shapeQueries look for a destination already visible in the indexed URL,
// which is the strongest signal an endpoint takes one.
func shapeQueries(domain string) []Query {
	return []Query{
		{
			Engine: Google,
			Query:  "site:" + domain + " inurl:\"=http\"",
			Why:    "a parameter value that is already an absolute URL",
		},
		{
			Engine: Google,
			Query:  "site:" + domain + " inurl:\"=%2F%2F\"",
			Why:    "an encoded protocol-relative destination",
		},
		{
			Engine: Google,
			Query:  "site:" + domain + " inurl:redirect inurl:http",
			Why:    "a redirect endpoint with a URL in the query string",
		},
		{
			Engine: Google,
			Query:  "site:" + domain + " inurl:\"/oauth\" inurl:redirect_uri",
			Why:    "an OAuth authorize endpoint, where a bypass is token theft",
		},
		{
			Engine: Google,
			Query:  "site:" + domain + " inurl:logout inurl:redirect",
			Why:    "logout redirects, routinely unvalidated where login is not",
		},
	}
}

// codeQueries search source rather than the web, which finds the parameter
// names and guards an organization actually uses.
func codeQueries(domain string) []Query {
	name := apexLabel(domain)

	return []Query{
		{
			Engine: GitHub,
			Query:  "\"" + domain + "\" \"redirect_uri\"",
			Why:    "registered redirect URIs referencing the target",
		},
		{
			Engine: GitHub,
			Query:  "org:" + name + " \"location.href=\"",
			Why:    "client-side navigation sinks in the organization's code",
		},
		{
			Engine: GitHub,
			Query:  "org:" + name + " \"safeDomains\" OR \"allowedHosts\" OR \"isSafeUrl\"",
			Why:    "a destination allowlist, whatever it happens to be called",
		},
	}
}

// apexLabel is the organization-ish label of a domain, used as a GitHub org
// guess. It is a guess, and the query is cheap to correct by hand.
func apexLabel(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}

	return parts[len(parts)-2]
}
