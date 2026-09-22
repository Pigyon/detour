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
	"sort"
	"strings"

	"github.com/nedlir/detour/internal/model"
)

const (
	fileJSONL = "findings.jsonl"
	fileJSON  = "findings.json"
	fileMD    = "report.md"
	fileSARIF = "report.sarif"
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

	for part := range strings.SplitSeq(raw, ",") {
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

	if err := writeMarkdown(filepath.Join(dir, fileMD), unique); err != nil {
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

	scored := ScoreAll(findings)

	if _, err := fmt.Fprintf(&b, "%d distinct root causes, highest severity first.\n", len(scored)); err != nil {
		return fmt.Errorf("writing report heading: %w", err)
	}

	for _, s := range scored {
		if err := writeScoredMarkdown(&b, s); err != nil {
			return err
		}
	}

	return writeFile(path, []byte(b.String()))
}

func writeScoredMarkdown(b *strings.Builder, s Scored) error {
	if _, err := fmt.Fprintf(b, "\n## %s: %s\n\n", heading(s.Finding), techniqueTitle(s.TechniqueID)); err != nil {
		return fmt.Errorf("writing finding heading: %w", err)
	}

	if _, err := fmt.Fprintf(b, "- suggested severity: **%s** (%.1f, derived from capabilities, not asserted)\n",
		s.Score.Severity, s.Score.Base); err != nil {
		return fmt.Errorf("writing severity: %w", err)
	}

	if _, err := fmt.Fprintf(b, "- cvss 3.1: `%s`\n- cvss 4.0: `%s`\n", s.Score.CVSS31, s.Score.CVSS40); err != nil {
		return fmt.Errorf("writing vectors: %w", err)
	}

	if err := writeFindingMarkdown(b, s.Finding); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(b, "- root cause: `%s`\n", RootCause(s.Finding)); err != nil {
		return fmt.Errorf("writing root cause: %w", err)
	}

	_, err := fmt.Fprintf(b, "- remediation: %s\n", Remediation(s.TechniqueID))

	return err
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
	names := make([]string, 0, 16)

	names = append(names, escalateNames(c)...)

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

// escalateNames lists the escalation capabilities a set carries. It mirrors
// the escalate package's own list, kept here so report does not depend on it.
func escalateNames(c model.CapabilitySet) []string {
	out := []string{}

	for _, entry := range []struct {
		on   bool
		name string
	}{
		{c.OAuthRedirectURI, "oauth.redirect_uri"},
		{c.PostLogoutRedirect, "oidc.post_logout_redirect_uri"},
		{c.SAMLRelayState, "saml.relaystate"},
		{c.DataScheme, "data_scheme"},
		{c.CSPBypass, "csp_bypass"},
		{c.CSRFReferer, "csrf.referer_bypass"},
		{c.CachePoisoned, "cache_poisoned"},
		{c.CrossProtocol, "cross_protocol"},
		{c.PhishingVector, "phishing_vector"},
	} {
		if entry.on {
			out = append(out, entry.name)
		}
	}

	return out
}
