package report

import (
	"fmt"
	"math"

	"github.com/nedlir/detour/internal/model"
)

// metricValues are the CVSS 3.1 base metric weights, straight out of the
// specification. Nothing here is detour's own judgment; the judgment is only
// in which letter a capability earns, in metricsFor below.
var (
	avWeight  = map[byte]float64{'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
	acWeight  = map[byte]float64{'L': 0.77, 'H': 0.44}
	uiWeight  = map[byte]float64{'N': 0.85, 'R': 0.62}
	ciaWeight = map[byte]float64{'H': 0.56, 'L': 0.22, 'N': 0.0}
	// prWeight is keyed by scope, because Privileges Required's own weight
	// differs when Scope is Changed, per the specification.
	prWeight = map[byte]map[byte]float64{
		'U': {'N': 0.85, 'L': 0.62, 'H': 0.27},
		'C': {'N': 0.85, 'L': 0.68, 'H': 0.5},
	}
)

// metrics is one CVSS 3.1 base vector, one letter per component.
type metrics struct {
	av, ac, pr, ui, scope, c, i, a byte
}

// SuggestSeverity derives a CVSS 3.1 vector and score from caps.
//
// Every finding in this class needs a victim to follow a link, so UI is R
// throughout except where the fetch is server-side (SSRFChain), which needs
// no user at all. Scope is Changed throughout: the vulnerable component is
// the redirect validator, but what it costs sits in the browser's security
// context, which is NVD's own convention for CWE-601. Nothing here lowers a
// capability's component below the bare-redirect baseline; escalations only
// ever raise a component, matching how caps themselves only ever accumulate.
func SuggestSeverity(caps model.CapabilitySet) model.Severity {
	m := metrics{av: 'N', ac: 'L', pr: 'N', ui: 'R', scope: 'C', c: 'L', i: 'L', a: 'N'}

	// A multi-hop chain is genuinely harder to pull off, and Attack
	// Complexity is an exploitability discount: raising it can lower the
	// total score even as other capabilities raise impact. That is correct
	// CVSS behavior, not a bug in the derivation.
	if caps.HopCount > 1 {
		m.ac = 'H'
	}

	raise := func(c, i, a byte) {
		m.c = maxByWeight(m.c, c, ciaWeight)
		m.i = maxByWeight(m.i, i, ciaWeight)
		m.a = maxByWeight(m.a, a, ciaWeight)
	}

	// Token or code theft off a trusted SSO redirect: the strongest
	// confidentiality loss this class has, per REFERENCE.md's own framing of
	// OAuth and SAML/WS-Federation findings as "not Low."
	if caps.OAuthRedirectURI || caps.SAMLRelayState {
		raise('H', 'L', 'N')
	}

	// A fetcher that follows the redirect server-side needs no victim at
	// all, and reaching an internal network is a strong confidentiality
	// loss in its own right.
	if caps.SSRFChain {
		m.ui = 'N'

		raise('H', 'L', 'N')
	}

	// javascript:/data: scheme execution and a defeated CSP both mean
	// script runs in the page's own context, which is full integrity loss
	// and, through session access, full confidentiality loss too.
	if caps.JavaScriptScheme || caps.DataScheme || caps.CSPBypass {
		raise('H', 'H', 'N')
	}

	// REFERENCE.md names what leaks here explicitly: reset tokens, JWTs,
	// session ids. That is a full confidentiality loss, not a partial one.
	if caps.RefererLeak {
		raise('H', 'N', 'N')
	}

	// A same-domain Referer bypass enables a CSRF whose own impact is
	// unknown; it earns only the integrity floor an unspecified state
	// change implies, not more.
	if caps.CSRFReferer {
		raise('N', 'L', 'N')
	}

	// Shared-cache poisoning affects every later visitor the cache serves,
	// not just one victim. CVSS has no metric for that blast radius; the
	// one component it does affect is the integrity of what the cache
	// serves next.
	if caps.CachePoisoned {
		raise('N', 'L', 'N')
	}

	score := baseScore(m)

	return model.Severity{Vector: vectorString(m), Score: score, Rating: rating(score)}
}

// maxByWeight returns whichever of the candidates weighs the most, by weight.
func maxByWeight(current, candidate byte, weight map[byte]float64) byte {
	if weight[candidate] > weight[current] {
		return candidate
	}

	return current
}

// baseScore computes the CVSS 3.1 base score from m, following the
// specification's formula exactly: this part is arithmetic, not judgment.
func baseScore(m metrics) float64 {
	iss := 1 - (1-ciaWeight[m.c])*(1-ciaWeight[m.i])*(1-ciaWeight[m.a])
	if iss <= 0 {
		return 0
	}

	exploitability := 8.22 * avWeight[m.av] * acWeight[m.ac] * prWeight[m.scope][m.pr] * uiWeight[m.ui]

	if m.scope == 'U' {
		return roundUp(math.Min(6.42*iss+exploitability, 10))
	}

	impact := 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)

	return roundUp(math.Min(1.08*(impact+exploitability), 10))
}

// roundUp is CVSS 3.1's own rounding rule: up to the nearest 0.1, defined in
// integer arithmetic so floating point never rounds the wrong way at a
// boundary.
func roundUp(num float64) float64 {
	intInput := math.Round(num * 100000)
	if math.Mod(intInput, 10000) == 0 {
		return intInput / 100000.0
	}

	return (math.Floor(intInput/10000) + 1) / 10.0
}

// rating is the CVSS 3.1 qualitative severity band.
func rating(score float64) string {
	switch {
	case score == 0:
		return "none"
	case score < 4.0:
		return "low"
	case score < 7.0:
		return "medium"
	case score < 9.0:
		return "high"
	default:
		return "critical"
	}
}

func vectorString(m metrics) string {
	return fmt.Sprintf("CVSS:3.1/AV:%c/AC:%c/PR:%c/UI:%c/S:%c/C:%c/I:%c/A:%c",
		m.av, m.ac, m.pr, m.ui, m.scope, m.c, m.i, m.a)
}
