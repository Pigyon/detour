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

// Target is a host or URL under test.
type Target struct {
	URL  string `json:"url"`
	Host string `json:"host"`
}

// Attempt is one payload fired at a candidate.
type Attempt struct {
	Candidate NavigationCandidate `json:"candidate"`
	Payload   string              `json:"payload"`
	Technique string              `json:"technique"`
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
	Verdict       string              `json:"verdict,omitempty"`
}

// NewFinding returns a finding with schema version set and slices initialized.
func NewFinding() Finding {
	return Finding{
		SchemaVersion: FindingSchemaVersion,
		Evidence:      []string{},
		Capabilities:  NewCapabilitySet(),
	}
}
