// Package report filters findings and writes jsonl, json, and markdown reports.
package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nedlir/detour/internal/model"
)

const (
	fileJSONL = "findings.jsonl"
	fileJSON  = "findings.json"
	fileMD    = "report.md"
	dirPerm   = 0o750
	filePerm  = 0o600
)

var knownMechanisms = map[string]struct{}{
	"header":  {},
	"js":      {},
	"meta":    {},
	"refresh": {},
	"crlf":    {},
	"blob":    {},
	"query":   {},
}

// ParseFilter splits a comma-separated mechanism list. An empty string means no filter.
func ParseFilter(raw string) (map[string]struct{}, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	allow := map[string]struct{}{}

	for _, part := range strings.Split(raw, ",") {
		mech := strings.ToLower(strings.TrimSpace(part))
		if mech == "" {
			continue
		}

		if _, ok := knownMechanisms[mech]; !ok {
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

// Write dumps findings.jsonl, findings.json, and report.md under dir.
func Write(dir string, findings []model.Finding) error {
	if dir == "" {
		return errors.New("empty report directory")
	}

	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("creating report directory: %w", err)
	}

	if err := writeJSONL(filepath.Join(dir, fileJSONL), findings); err != nil {
		return err
	}

	if err := writeJSON(filepath.Join(dir, fileJSON), findings); err != nil {
		return err
	}

	if err := writeMarkdown(filepath.Join(dir, fileMD), findings); err != nil {
		return err
	}

	return nil
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

func writeJSON(path string, findings []model.Finding) error {
	if findings == nil {
		findings = []model.Finding{}
	}

	raw, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding findings json: %w", err)
	}

	raw = append(raw, '\n')

	return writeFile(path, raw)
}

func writeMarkdown(path string, findings []model.Finding) error {
	var b strings.Builder

	b.WriteString("# detour findings\n\n")

	if _, err := fmt.Fprintf(&b, "%d confirmed.\n", len(findings)); err != nil {
		return fmt.Errorf("writing report heading: %w", err)
	}

	for _, f := range findings {
		if err := writeFindingMarkdown(&b, f); err != nil {
			return err
		}
	}

	return writeFile(path, []byte(b.String()))
}

func writeFindingMarkdown(b *strings.Builder, f model.Finding) error {
	if _, err := fmt.Fprintf(b, "\n## %s\n\n", heading(f)); err != nil {
		return fmt.Errorf("writing finding heading: %w", err)
	}

	if _, err := fmt.Fprintf(b, "- source: %s\n", f.Candidate.SourceURL); err != nil {
		return fmt.Errorf("writing finding source: %w", err)
	}

	if _, err := fmt.Fprintf(b, "- mechanism: %s\n", f.Mechanism); err != nil {
		return fmt.Errorf("writing finding mechanism: %w", err)
	}

	if f.Verdict != "" {
		if _, err := fmt.Fprintf(b, "- verdict: %s\n", f.Verdict); err != nil {
			return fmt.Errorf("writing finding verdict: %w", err)
		}
	}

	if _, err := fmt.Fprintf(b, "- payload: `%s`\n", f.Payload); err != nil {
		return fmt.Errorf("writing finding payload: %w", err)
	}

	if f.Repro != "" {
		if _, err := fmt.Fprintf(b, "- repro: `%s`\n", f.Repro); err != nil {
			return fmt.Errorf("writing finding repro: %w", err)
		}
	}

	caps := capabilityList(f.Capabilities)
	if len(caps) > 0 {
		if _, err := fmt.Fprintf(b, "- capabilities: %s\n", strings.Join(caps, ", ")); err != nil {
			return fmt.Errorf("writing finding capabilities: %w", err)
		}
	}

	for _, ev := range f.Evidence {
		if _, err := fmt.Fprintf(b, "- evidence: %s\n", ev); err != nil {
			return fmt.Errorf("writing finding evidence: %w", err)
		}
	}

	return nil
}

func heading(f model.Finding) string {
	if f.TechniqueID != "" {
		return f.TechniqueID
	}

	return "finding"
}

func capabilityList(c model.CapabilitySet) []string {
	names := make([]string, 0, 8)

	if c.RedirectExternal {
		names = append(names, "redirect.external")
	}

	if c.BrowserConfirmed {
		names = append(names, "browser_confirmed")
	}

	if c.InputControlled {
		names = append(names, "input_controlled")
	}

	if c.JavaScriptScheme {
		names = append(names, "javascript_scheme")
	}

	if c.SSRFChain {
		names = append(names, "ssrf_chain")
	}

	if c.RefererLeak {
		names = append(names, "referer_leak")
	}

	if c.OAuthRedirectURI {
		names = append(names, "oauth.redirect_uri")
	}

	if c.HopCount > 0 {
		names = append(names, fmt.Sprintf("hop_count=%d", c.HopCount))
	}

	sort.Strings(names)

	return names
}

func writeFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, filePerm); err != nil {
		return fmt.Errorf("writing %s: %w", filepath.Base(path), err)
	}

	return nil
}
