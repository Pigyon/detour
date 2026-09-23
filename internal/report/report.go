// Package report filters findings and writes jsonl, json, and markdown reports.
package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/payload"
)

const (
	fileJSONL   = "findings.jsonl"
	fileJSON    = "findings.json"
	fileReport  = "REPORT.md"
	dirFindings = "findings"
	fileSARIF   = "report.sarif"
	dirPerm     = 0o750
	filePerm    = 0o600
)

// ParseFilter splits a comma-separated mechanism list. An empty string means no filter.
func ParseFilter(raw string) (map[string]struct{}, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	allow := map[string]struct{}{}

	for part := range strings.SplitSeq(raw, ",") {
		mech := strings.ToLower(strings.TrimSpace(part))
		if mech == "" {
			continue
		}

		if !payload.KnownMechanism(mech) {
			return nil, fmt.Errorf("unknown mechanism %q", mech)
		}

		allow[mech] = struct{}{}
	}

	if len(allow) == 0 {
		return nil, errors.New("empty mechanism filter")
	}

	return allow, nil
}

// Apply keeps findings whose mechanism is in allow. A nil allow keeps all.
func Apply(findings []model.Finding, allow map[string]struct{}) []model.Finding {
	if len(allow) == 0 {
		return findings
	}

	out := []model.Finding{}

	for _, f := range findings {
		if _, ok := allow[f.Mechanism]; ok {
			out = append(out, f)
		}
	}

	return out
}

// Write dumps the report set under dir.
//
// findings.jsonl is the source of truth and is written exactly as the run
// produced it. The json, markdown, and sarif files are projections of it, and
// the last three dedupe by root cause because a reader wants defects, not
// demonstrations.
func Write(dir string, findings []model.Finding) error {
	return WriteVersion(dir, findings, "dev")
}

// WriteVersion is Write with the tool version recorded in the SARIF log.
func WriteVersion(dir string, findings []model.Finding, version string) error {
	if dir == "" {
		return errors.New("empty report directory")
	}

	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("creating report directory: %w", err)
	}

	if err := writeJSONL(filepath.Join(dir, fileJSONL), findings); err != nil {
		return err
	}

	unique := Dedupe(findings)

	if err := writeJSON(filepath.Join(dir, fileJSON), unique); err != nil {
		return err
	}

	if err := writeRunReport(filepath.Join(dir, fileReport), unique); err != nil {
		return err
	}

	if err := writeFindingReports(filepath.Join(dir, dirFindings), unique); err != nil {
		return err
	}

	return writeSARIF(filepath.Join(dir, fileSARIF), unique, version)
}

func writeSARIF(path string, findings []model.Finding, version string) error {
	raw, err := SARIF(findings, version)
	if err != nil {
		return err
	}

	return writeFile(path, raw)
}

func writeJSONL(path string, findings []model.Finding) error {
	var b strings.Builder

	enc := json.NewEncoder(&b)
	for _, f := range findings {
		if err := enc.Encode(f); err != nil {
			return fmt.Errorf("encoding findings jsonl: %w", err)
		}
	}

	return writeFile(path, []byte(b.String()))
}

// writeJSON emits the deduped findings with their root cause attached.
func writeJSON(path string, findings []model.Finding) error {
	out := make([]reportedFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, reportedFinding{
			Finding:     f,
			RootCause:   RootCause(f),
			Fingerprint: Fingerprint(f),
		})
	}

	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding findings json: %w", err)
	}

	raw = append(raw, '\n')

	return writeFile(path, raw)
}

// reportedFinding is a finding plus the defect it belongs to.
type reportedFinding struct {
	model.Finding
	RootCause   string `json:"root_cause"`
	Fingerprint string `json:"fingerprint"`
}

// writeRunReport writes one report covering everything the run found, grouped
// by the URL it was found on.
func writeRunReport(path string, findings []model.Finding) error {
	var b strings.Builder

	b.WriteString("# Open redirects\n\n")

	if len(findings) == 0 {
		b.WriteString("No open redirects were confirmed.\n")

		return writeFile(path, []byte(b.String()))
	}

	fmt.Fprintf(&b, "%d confirmed on %d endpoints.\n", len(findings), len(byEndpoint(findings)))

	for _, group := range byEndpoint(findings) {
		fmt.Fprintf(&b, "\n## %s\n\n", group.endpoint)

		for _, f := range group.findings {
			fmt.Fprintf(&b, "- **%s** via `%s`\n", techniqueLine(f.TechniqueID), f.Payload)
			fmt.Fprintf(&b, "  - %s\n", f.Repro)
			fmt.Fprintf(&b, "  - report: `%s/REPORT.md`\n", findingDir(f))
		}
	}

	return writeFile(path, []byte(b.String()))
}

// writeFindingReports writes one submittable report per finding, each in its
// own directory so it can be handed over on its own.
func writeFindingReports(dir string, findings []model.Finding) error {
	for _, f := range findings {
		into := filepath.Join(dir, findingDir(f))
		if err := os.MkdirAll(into, dirPerm); err != nil {
			return fmt.Errorf("creating finding directory: %w", err)
		}

		if err := writeFile(filepath.Join(into, fileReport), []byte(Render(f))); err != nil {
			return err
		}
	}

	return nil
}

// findingDir names a finding's directory: the technique and enough of the
// fingerprint to stay unique, so the same defect lands in the same place on
// every run.
func findingDir(f model.Finding) string {
	id := f.TechniqueID
	if id == "" {
		id = "finding"
	}

	return id + "-" + Fingerprint(f)[:8]
}

// endpointGroup is the findings on one URL.
type endpointGroup struct {
	endpoint string
	findings []model.Finding
}

// byEndpoint groups findings by the URL they were found on, first seen first.
func byEndpoint(findings []model.Finding) []endpointGroup {
	index := map[string]int{}
	out := []endpointGroup{}

	for _, f := range findings {
		endpoint := f.Candidate.SourceURL

		at, seen := index[endpoint]
		if !seen {
			index[endpoint] = len(out)
			out = append(out, endpointGroup{endpoint: endpoint, findings: []model.Finding{f}})

			continue
		}

		out[at].findings = append(out[at].findings, f)
	}

	return out
}

func writeFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, filePerm); err != nil {
		return fmt.Errorf("writing %s: %w", filepath.Base(path), err)
	}

	return nil
}

// ReadJSONL loads findings written by a previous run. Blank lines are
// tolerated so a hand-edited list still parses.
func ReadJSONL(path string) ([]model.Finding, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is the operator-supplied findings list.
	if err != nil {
		return nil, fmt.Errorf("reading findings list: %w", err)
	}

	return DecodeJSONL(raw)
}

// DecodeJSONL parses a findings stream.
func DecodeJSONL(raw []byte) ([]model.Finding, error) {
	out := []model.Finding{}
	dec := json.NewDecoder(bytes.NewReader(raw))

	for {
		var f model.Finding

		err := dec.Decode(&f)
		if errors.Is(err, io.EOF) {
			return out, nil
		}

		if err != nil {
			return nil, fmt.Errorf("decoding finding: %w", err)
		}

		out = append(out, f)
	}
}
