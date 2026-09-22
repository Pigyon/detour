package report

import (
	"sort"
	"strings"

	"github.com/nedlir/detour/internal/model"
)

// Severity bands, named the way a triager reads them.
const (
	SeverityNone     = "none"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Score is a suggested severity derived from what a finding proves.
//
// It is derived, never asserted. Capabilities are the source of truth: the
// vectors below are a reading of them offered to save a triager time, and a
// program's own rubric overrides it. Nothing in detour branches on this.
type Score struct {
	Severity string  `json:"severity"`
	Base     float64 `json:"base"`
	// CVSS31 and CVSS40 are vector strings, for pasting into a report form.
	CVSS31 string `json:"cvss_3_1"`
	CVSS40 string `json:"cvss_4_0"`
	// Because lists the capabilities that produced this reading, so the
	// number is never a bare assertion.
	Because []string `json:"because"`
}

// capabilityWeight is what each proven fact contributes.
//
// The shape of this table is the argument: a bare external redirect is Low and
// everyone knows it, and the things that move the number are the ones that
// change what an attacker can actually do with it.
var capabilityWeight = []struct {
	name   string
	weight float64
	on     func(model.CapabilitySet) bool
}{
	{"redirect.external", 2.0, func(c model.CapabilitySet) bool { return c.RedirectExternal }},
	{"input_controlled", 1.5, func(c model.CapabilitySet) bool { return c.InputControlled }},
	{"browser_confirmed", 1.0, func(c model.CapabilitySet) bool { return c.BrowserConfirmed }},
	{"oauth.redirect_uri", 4.5, func(c model.CapabilitySet) bool { return c.OAuthRedirectURI }},
	{"javascript_scheme", 4.0, func(c model.CapabilitySet) bool { return c.JavaScriptScheme }},
	{"ssrf_chain", 3.5, func(c model.CapabilitySet) bool { return c.SSRFChain }},
	{"saml.relaystate", 3.0, func(c model.CapabilitySet) bool { return c.SAMLRelayState }},
	{"data_scheme", 2.5, func(c model.CapabilitySet) bool { return c.DataScheme }},
	{"oidc.post_logout_redirect_uri", 2.0, func(c model.CapabilitySet) bool { return c.PostLogoutRedirect }},
	{"cache_poisoned", 2.0, func(c model.CapabilitySet) bool { return c.CachePoisoned }},
	{"csp_bypass", 1.5, func(c model.CapabilitySet) bool { return c.CSPBypass }},
	{"referer_leak", 1.0, func(c model.CapabilitySet) bool { return c.RefererLeak }},
	{"csrf.referer_bypass", 1.0, func(c model.CapabilitySet) bool { return c.CSRFReferer }},
	{"phishing_vector", 1.0, func(c model.CapabilitySet) bool { return c.PhishingVector }},
	{"cross_protocol", 0.5, func(c model.CapabilitySet) bool { return c.CrossProtocol }},
}

const (
	maxBase       = 10.0
	mediumFloor   = 4.0
	highFloor     = 7.0
	criticalFloor = 9.0
)

// Derive reads a capability set into a suggested severity.
func Derive(c model.CapabilitySet) Score {
	base := 0.0
	because := []string{}

	for _, entry := range capabilityWeight {
		if !entry.on(c) {
			continue
		}

		base += entry.weight
		because = append(because, entry.name)
	}

	// An unconfirmed candidate has not proven it redirects at all, so it
	// cannot outrank something that has.
	if !c.RedirectExternal {
		base = 0
	}

	if c.HopCount > 0 {
		base += 0.5

		because = append(because, "hop_count")
	}

	base = min(base, maxBase)

	return Score{
		Severity: band(base),
		Base:     round1(base),
		CVSS31:   vector31(c),
		CVSS40:   vector40(c),
		Because:  because,
	}
}

func band(base float64) string {
	switch {
	case base <= 0:
		return SeverityNone
	case base >= criticalFloor:
		return SeverityCritical
	case base >= highFloor:
		return SeverityHigh
	case base >= mediumFloor:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// vector31 builds a CVSS 3.1 vector.
//
// An open redirect is network, low complexity, no privileges, and needs a user
// to follow the link. What varies is scope and impact: a javascript: sink runs
// script in the origin, and an OAuth bypass hands over a token.
func vector31(c model.CapabilitySet) string {
	parts := []string{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R"}

	scope := "S:U"
	conf, integ := "C:N", "I:N"

	switch {
	case c.JavaScriptScheme || c.DataScheme:
		scope, conf, integ = "S:C", "C:H", "I:H"
	case c.OAuthRedirectURI || c.SAMLRelayState:
		scope, conf, integ = "S:C", "C:H", "I:L"
	case c.SSRFChain:
		scope, conf = "S:C", "C:L"
	case c.RefererLeak || c.PostLogoutRedirect:
		conf = "C:L"
	case c.RedirectExternal:
		integ = "I:L"
	}

	parts = append(parts, scope, conf, integ, "A:N")

	return strings.Join(parts, "/")
}

// vector40 builds a CVSS 4.0 vector over the same facts.
func vector40(c model.CapabilitySet) string {
	parts := []string{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A"}

	vc, vi := "VC:N", "VI:N"
	sc, si := "SC:N", "SI:N"

	switch {
	case c.JavaScriptScheme || c.DataScheme:
		vc, vi, sc, si = "VC:H", "VI:H", "SC:H", "SI:H"
	case c.OAuthRedirectURI || c.SAMLRelayState:
		vc, vi, sc = "VC:H", "VI:L", "SC:H"
	case c.SSRFChain:
		vc, sc = "VC:L", "SC:L"
	case c.RefererLeak || c.PostLogoutRedirect:
		vc = "VC:L"
	case c.RedirectExternal:
		vi = "VI:L"
	}

	parts = append(parts, vc, vi, "VA:N", sc, si, "SA:N")

	return strings.Join(parts, "/")
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}

// Scored pairs a finding with its derived severity for reporting.
type Scored struct {
	model.Finding
	Score Score `json:"score"`
}

// ScoreAll derives a severity for every finding, highest first.
func ScoreAll(findings []model.Finding) []Scored {
	out := make([]Scored, 0, len(findings))
	for _, f := range findings {
		out = append(out, Scored{Finding: f, Score: Derive(f.Capabilities)})
	}

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Score.Base > out[j].Score.Base
	})

	return out
}
