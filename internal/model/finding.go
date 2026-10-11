// Package model holds the engine's core types, centered on NavigationCandidate.
package model

const (
	// FindingSchemaVersion is the schema_version written on every finding record.
	FindingSchemaVersion = "1"
	// VerdictConfirmed is a server-side resolver decision.
	VerdictConfirmed = "confirmed"
	// VerdictCandidate needs headless confirmation (browser-quirk families).
	VerdictCandidate = "candidate"
)

// FieldPath locates a URL inside a decoded representation (JSONPath-style).
type FieldPath string

// Decoder is one reversible transform in a DecoderChain.
type Decoder struct {
	Kind string `json:"kind"`
}

// Validator is a guard extracted from JS or inferred from server behaviour.
type Validator struct {
	Name      string   `json:"name,omitempty"`
	Source    string   `json:"source,omitempty"`
	Kind      string   `json:"kind,omitempty"`
	Allowlist []string `json:"allowlist,omitempty"`
}

// Clone returns a deep copy so callers cannot mutate the original allowlist.
func (v *Validator) Clone() *Validator {
	if v == nil {
		return nil
	}

	out := *v
	if v.Allowlist != nil {
		out.Allowlist = append([]string{}, v.Allowlist...)
	}

	return &out
}

// Severity is a suggested CVSS 3.1 score, derived from a finding's
// capabilities. It is a suggestion, not an assertion: the program's own
// rubric is the one that decides what a submission is actually worth.
type Severity struct {
	Vector string  `json:"vector"`
	Score  float64 `json:"score"`
	Rating string  `json:"rating"`
}

// Finding is a capability-scored result. CVSS is derived later, not stored here.
type Finding struct {
	SchemaVersion string              `json:"schema_version"`
	TechniqueID   string              `json:"technique_id"`
	Mechanism     string              `json:"mechanism,omitempty"`
	Payload       string              `json:"payload"`
	Rationale     string              `json:"rationale,omitempty"`
	Precedent     string              `json:"precedent,omitempty"`
	Candidate     NavigationCandidate `json:"candidate"`
	Capabilities  CapabilitySet       `json:"capabilities"`
	Evidence      []string            `json:"evidence,omitempty"`
	Repro         string              `json:"repro,omitempty"`
	// ProbeURL is the concrete request that produced this finding. The
	// browser stage replays it, so it must be usable as written.
	ProbeURL string `json:"probe_url,omitempty"`
	// Artifacts names the files the browser stage wrote for this finding, so
	// a report can point at the screenshot and HAR that prove it rather than
	// leaving them in a directory nothing references.
	Artifacts []string `json:"artifacts,omitempty"`
	Verdict   string   `json:"verdict,omitempty"`
	// Severity is filled in by report.SuggestSeverity. Omitted when nothing
	// has computed it yet, so a finding that never reached that stage does
	// not carry a zero-value score that could be mistaken for a real one.
	Severity *Severity `json:"severity,omitempty"`
}

// NewFinding returns a finding with schema version set and slices initialized.
func NewFinding() Finding {
	return Finding{
		SchemaVersion: FindingSchemaVersion,
		Evidence:      []string{},
		Capabilities:  NewCapabilitySet(),
	}
}
