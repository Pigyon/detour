package js

import (
	"strings"
)

// Severity separates a lead that needs a browser from a note that is true but
// not worth a report on its own.
const (
	// SeverityCandidate needs headless confirmation before it is a finding.
	SeverityCandidate = "candidate"
	// SeverityInfo is real but not reportable alone, such as an allowlist that
	// permits http.
	SeverityInfo = "info"
)

// Verdict is one concrete way a guard can be beaten, with the discrepancy
// named. Naming the discrepancy is what keeps static evidence honest: detour
// says what it read and what it expects, never that it proved a redirect.
type Verdict struct {
	TechniqueID string `json:"technique_id"`
	Severity    string `json:"severity"`
	Sink        string `json:"sink"`
	// Discrepancy is the gap in plain words.
	Discrepancy string `json:"discrepancy"`
	// Payload is a destination built for this specific validator.
	Payload  string   `json:"payload,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
}

// canaryHost is the placeholder attacker host in generated payloads. The
// engine substitutes the real canary when it fires them.
const canaryHost = "{{canary}}"

// verdictsFor reports every way a sink can be reached with an attacker
// destination, given the guard that protects it.
func verdictsFor(sink Sink) []Verdict {
	if sink.Validator == nil {
		return unguardedVerdicts(sink)
	}

	return guardedVerdicts(sink, *sink.Validator)
}

// unguardedVerdicts covers a navigation with no guard at all.
func unguardedVerdicts(sink Sink) []Verdict {
	technique := "OR-C01"
	discrepancy := "navigation sink with no guard in the enclosing scope"

	if sink.Origin.Kind == OriginHash {
		technique = "OR-C02"
		discrepancy = "sink is fed from location.hash, which never reaches the server"
	}

	if sink.Kind == SinkTopLocation {
		technique = "OR-C03"
		discrepancy = "framed document drives top-level navigation with no guard"
	}

	return []Verdict{{
		TechniqueID: technique,
		Severity:    SeverityCandidate,
		Sink:        sink.Kind,
		Discrepancy: discrepancy,
		Payload:     "https://" + canaryHost + "/",
		Evidence:    sinkEvidence(sink),
	}}
}

// guardedVerdicts is the allowlist attack: for each way the guard is loose,
// build the destination that slips past it.
func guardedVerdicts(sink Sink, v Validator) []Verdict {
	out := []Verdict{}

	if !v.Resolved {
		return append(out, Verdict{
			TechniqueID: "OR-C01",
			Severity:    SeverityInfo,
			Sink:        sink.Kind,
			Discrepancy: "sink is guarded by " + v.Name + ", whose body is not in this script",
			Evidence:    sinkEvidence(sink),
		})
	}

	out = append(out, matchVerdicts(sink, v)...)

	if !v.ChecksUserinfo {
		out = append(out, Verdict{
			TechniqueID: "OR-A01",
			Severity:    SeverityCandidate,
			Sink:        sink.Kind,
			Discrepancy: "guard never reads username or password, so userinfo can carry a different host",
			Payload:     "https://" + trusted(v) + "@" + canaryHost + "/",
			Evidence:    sinkEvidence(sink),
		})
	}

	out = append(out, schemeVerdicts(sink, v)...)
	out = append(out, decodeVerdicts(sink, v)...)

	return out
}

// matchVerdicts turns the guard's comparison style into the payload that beats
// it. Everything except exact equality has a bypass.
func matchVerdicts(sink Sink, v Validator) []Verdict {
	host := trusted(v)

	switch v.Kind {
	case MatchPrefix:
		return []Verdict{prefixVerdict(sink, host)}
	case MatchSuffix:
		return []Verdict{suffixVerdict(sink, host)}
	case MatchSubstring:
		return []Verdict{substringVerdict(sink, host)}
	case MatchRegex:
		return []Verdict{regexVerdict(sink, host)}
	case MatchUnknown:
		return []Verdict{{
			TechniqueID: "OR-C01",
			Severity:    SeverityCandidate,
			Sink:        sink.Kind,
			Discrepancy: "guard " + v.Name + " performs no host comparison detour could find",
			Payload:     "https://" + canaryHost + "/",
			Evidence:    sinkEvidence(sink),
		}}
	default:
		return nil
	}
}

func prefixVerdict(sink Sink, host string) Verdict {
	return Verdict{
		TechniqueID: "OR-A09",
		Severity:    SeverityCandidate,
		Sink:        sink.Kind,
		Discrepancy: "prefix match is unanchored at the right, so a longer host still matches",
		Payload:     "https://" + host + "." + canaryHost + "/",
		Evidence:    sinkEvidence(sink),
	}
}

func suffixVerdict(sink Sink, host string) Verdict {
	return Verdict{
		TechniqueID: "OR-A13",
		Severity:    SeverityCandidate,
		Sink:        sink.Kind,
		Discrepancy: "suffix match is unanchored at the left, so any host ending in it matches",
		Payload:     "https://" + canaryHost + "." + host + "/",
		Evidence:    sinkEvidence(sink),
	}
}

func substringVerdict(sink Sink, host string) Verdict {
	return Verdict{
		TechniqueID: "OR-A08",
		Severity:    SeverityCandidate,
		Sink:        sink.Kind,
		Discrepancy: "membership is a substring test over the whole URL, so the trusted host can sit anywhere in it",
		Payload:     "https://" + canaryHost + "/?" + host,
		Evidence:    sinkEvidence(sink),
	}
}

func regexVerdict(sink Sink, host string) Verdict {
	return Verdict{
		TechniqueID: "OR-A08",
		Severity:    SeverityCandidate,
		Sink:        sink.Kind,
		Discrepancy: "guard matches with a regular expression; confirm it is anchored at both ends",
		Payload:     "https://" + canaryHost + "/?" + host,
		Evidence:    sinkEvidence(sink),
	}
}

// schemeVerdicts covers the two scheme gaps: no scheme check at all lets
// javascript: through, and a check that admits http is a downgrade.
func schemeVerdicts(sink Sink, v Validator) []Verdict {
	out := []Verdict{}

	// A guard that constrains the scheme already keeps javascript: out, so
	// only a guard doing neither earns this verdict.
	if !v.ChecksScheme && !v.BlocksJavaScript {
		out = append(out, Verdict{
			TechniqueID: "OR-E01",
			Severity:    SeverityCandidate,
			Sink:        sink.Kind,
			Discrepancy: "guard does not restrict the scheme to http and https, so javascript: may reach the sink",
			Payload:     "javascript:alert(document.domain)",
			Evidence:    sinkEvidence(sink),
		})
	}

	if v.AllowsHTTP {
		out = append(out, Verdict{
			TechniqueID: "OR-E03",
			Severity:    SeverityInfo,
			Sink:        sink.Kind,
			Discrepancy: "allowlist permits http, giving an https to http downgrade on a trusted host",
			Payload:     "http://" + trusted(v) + "/",
			Evidence:    sinkEvidence(sink),
		})
	}

	return out
}

// decodeVerdicts flags the double-decode gap. A guard that decodes once where
// a sink decodes again sees a relative path while the browser sees an
// absolute URL.
func decodeVerdicts(sink Sink, v Validator) []Verdict {
	if v.DecodeCount != 1 {
		return nil
	}

	return []Verdict{{
		TechniqueID: "OR-B04",
		Severity:    SeverityCandidate,
		Sink:        sink.Kind,
		Discrepancy: "guard decodes its input once; if anything downstream decodes again the check saw a different value",
		Payload:     "https%3A%2F%2F" + canaryHost + "%2F",
		Evidence:    sinkEvidence(sink),
	}}
}

// trusted returns a host the guard accepts, for building a payload that wears
// it. It falls back to a placeholder when the allowlist is not in the script.
func trusted(v Validator) string {
	if len(v.Allowlist) > 0 {
		return strings.TrimPrefix(strings.TrimPrefix(v.Allowlist[0], "https://"), "http://")
	}

	if v.AllowlistRef != "" {
		return "{{allowed}}"
	}

	return "{{target}}"
}

func sinkEvidence(sink Sink) []string {
	out := []string{sink.Kind + " = " + sink.Expression}

	if sink.Function != "" {
		out = append(out, "in function "+sink.Function)
	}

	if sink.Origin.Kind != OriginUnknown {
		out = append(out, "origin "+sink.Origin.Kind)
	}

	if sink.Origin.Param != "" {
		out = append(out, "parameter "+sink.Origin.Param)
	}

	for _, g := range sink.Guards {
		out = append(out, "guard "+g)
	}

	return out
}
