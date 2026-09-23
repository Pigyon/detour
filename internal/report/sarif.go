package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nedlir/detour/internal/model"
)

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	// referenceBase is where a rule's helpUri points. Every technique id is an
	// anchor in REFERENCE.md, so a consumer can read why a finding matters.
	referenceBase = "https://github.com/nedlir/detour/blob/main/REFERENCE.md#"
	toolName      = "detour"
)

// SARIF 2.1.0 result levels.
const (
	levelError   = "error"
	levelWarning = "warning"
	levelNone    = "none"
)

// sarifLog is the subset of SARIF 2.1.0 detour emits.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string           `json:"name"`
	InformationURI string           `json:"informationUri"`
	Version        string           `json:"version"`
	Rules          []sarifRuleDescr `json:"rules"`
}

// sarifRuleDescr is a reportingDescriptor: one per technique id.
type sarifRuleDescr struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifText         `json:"shortDescription"`
	FullDescription  sarifText         `json:"fullDescription"`
	HelpURI          string            `json:"helpUri"`
	Properties       map[string]any    `json:"properties,omitempty"`
	DefaultConfig    sarifRuleDefaults `json:"defaultConfiguration"`
}

type sarifRuleDefaults struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID  string          `json:"ruleId"`
	Level   string          `json:"level"`
	Message sarifText       `json:"message"`
	Kind    string          `json:"kind,omitempty"`
	Locs    []sarifLocation `json:"locations"`
	// WebRequest and WebResponse are the DAST shape. A redirect finding has no
	// file and line, and pretending otherwise makes a consumer render
	// nonsense.
	WebRequest          *sarifWebRequest  `json:"webRequest,omitempty"`
	WebResponse         *sarifWebResponse `json:"webResponse,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifWebRequest struct {
	Protocol string            `json:"protocol"`
	Method   string            `json:"method"`
	Target   string            `json:"target"`
	Headers  map[string]string `json:"headers,omitempty"`
}

type sarifWebResponse struct {
	Protocol   string            `json:"protocol"`
	StatusCode int               `json:"statusCode,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
}

// SARIF renders findings as a SARIF 2.1.0 log.
//
// Every emitted technique gets a rule, so a consumer never sees a ruleId it
// cannot resolve, and each rule's helpUri lands on that technique's section of
// REFERENCE.md. Root cause becomes partialFingerprints, so a consumer dedupes
// the way detour does rather than by URL.
func SARIF(findings []model.Finding, version string) ([]byte, error) {
	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           toolName,
				InformationURI: "https://github.com/nedlir/detour",
				Version:        version,
				Rules:          rulesFor(findings),
			}},
			Results: resultsFor(findings),
		}},
	}

	raw, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding sarif: %w", err)
	}

	return append(raw, '\n'), nil
}

func rulesFor(findings []model.Finding) []sarifRuleDescr {
	worst := map[string]string{}

	for _, f := range findings {
		id := f.TechniqueID
		if id == "" {
			continue
		}

		if worst[id] == "" {
			worst[id] = levelForFinding(f)
		}
	}

	ids := TechniqueIDs(findings)
	out := make([]sarifRuleDescr, 0, len(ids))

	for _, id := range ids {
		out = append(out, sarifRuleDescr{
			ID:               id,
			Name:             id,
			ShortDescription: sarifText{Text: techniqueTitle(id)},
			FullDescription:  sarifText{Text: techniqueTitle(id) + ". " + Remediation(id)},
			HelpURI:          referenceBase + strings.ToLower(id),
			DefaultConfig:    sarifRuleDefaults{Level: worst[id]},
			Properties: map[string]any{
				"tags": []string{"security", "open-redirect", classOf(id)},
			},
		})
	}

	return out
}

func resultsFor(findings []model.Finding) []sarifResult {
	out := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		kind := kindFor(f)

		result := sarifResult{
			RuleID:  f.TechniqueID,
			Level:   levelForKind(kind, levelForFinding(f)),
			Message: sarifText{Text: message(f)},
			Kind:    kind,
			Locs: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.Candidate.SourceURL},
				},
			}},
			PartialFingerprints: map[string]string{"detourRootCause/v1": Fingerprint(f)},
			Properties: map[string]any{
				"verdict":   f.Verdict,
				"payload":   f.Payload,
				"mechanism": f.Mechanism,
				"rootCause": RootCause(f),
			},
		}

		if target := f.ProbeURL; target != "" {
			result.WebRequest = &sarifWebRequest{Protocol: "http", Method: "GET", Target: target}
		}

		if resp := webResponse(f); resp != nil {
			result.WebResponse = resp
		}

		out = append(out, result)
	}

	return out
}

// webResponse reconstructs the response evidence from what the finding
// recorded, which is what makes a SARIF result replayable.
func webResponse(f model.Finding) *sarifWebResponse {
	headers := map[string]string{}
	status := 0

	for _, line := range f.Evidence {
		switch {
		case strings.HasPrefix(line, "status "):
			_, _ = fmt.Sscanf(line, "status %d", &status)
		case strings.HasPrefix(line, "Location: "):
			headers["Location"] = strings.TrimPrefix(line, "Location: ")
		case strings.HasPrefix(line, "refresh: "):
			headers["Refresh"] = strings.TrimPrefix(line, "refresh: ")
		}
	}

	if status == 0 && len(headers) == 0 {
		return nil
	}

	return &sarifWebResponse{Protocol: "http", StatusCode: status, Headers: headers}
}

// levelForKind applies the SARIF 2.1.0 rule that a result which is not a
// failure carries no level.
//
// The spec allows `level` only when `kind` is "fail"; anything else must be
// "none" or absent. Emitting a candidate as `kind: open` with `level: warning`
// is rejected or misreported by consumers such as GitHub code scanning, and a
// third of the results in a typical run were that shape.
func levelForKind(kind, level string) string {
	if kind != "fail" {
		return levelNone
	}

	return level
}

// levelForFinding is how loudly a consumer should report this finding.
//
// detour does not score severity. A redirect that reaches an authorization
// endpoint or executes script is worth more attention than one that does not,
// and that is as far as the judgement goes; the program's own rubric decides
// the rest.
func levelForFinding(f model.Finding) string {
	c := f.Capabilities
	if c.JavaScriptScheme || c.DataScheme || c.OAuthRedirectURI || c.SAMLRelayState || c.SSRFChain {
		return levelError
	}

	return levelWarning
}

// kindFor separates a proven finding from one still awaiting a browser.
func kindFor(f model.Finding) string {
	if f.Verdict == model.VerdictCandidate {
		return "open"
	}

	return "fail"
}

// message is the one-line summary a SARIF consumer shows.
func message(f model.Finding) string {
	var b strings.Builder

	b.WriteString(techniqueTitle(f.TechniqueID))

	if f.Candidate.ParamName != "" {
		b.WriteString(" in parameter ")
		b.WriteString(f.Candidate.ParamName)
	}

	b.WriteString(", reached with payload ")
	b.WriteString(f.Payload)
	b.WriteString(".")

	return b.String()
}

// classOf maps a technique id to its REFERENCE.md class.
func classOf(id string) string {
	if len(id) < 4 {
		return "unknown"
	}

	switch id[3] {
	case 'A':
		return "parser-differential"
	case 'B':
		return "opaque-destination"
	case 'C':
		return "client-side"
	case 'D':
		return "infrastructure"
	case 'E':
		return "scheme-abuse"
	case 'F':
		return "escalation"
	default:
		return "unknown"
	}
}
