package report_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	mechHeader    = "header"
	techA01       = "OR-A01"
	statusLine    = "status 302"
	canaryPayload = "https://canary.invalid"
)

func TestParseFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		want    []string
		wantErr bool
	}{
		{name: "empty", in: "", want: nil},
		{name: "one", in: mechHeader, want: []string{mechHeader}},
		{name: "list", in: mechHeader + ", crlf,query", want: []string{"crlf", mechHeader, mechQuery}},
		{name: "unknown", in: mechHeader + ",nope", wantErr: true},
		{name: "commas only", in: ",,", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := report.ParseFilter(tt.in)
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)

			if tt.want == nil {
				assert.Nil(t, got)

				return
			}

			require.Len(t, got, len(tt.want))

			for _, mech := range tt.want {
				_, ok := got[mech]
				assert.True(t, ok, mech)
			}
		})
	}
}

func TestApply(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{TechniqueID: techA01, Mechanism: mechQuery},
		{TechniqueID: "OR-D01", Mechanism: mechHeader},
		{TechniqueID: "OR-A11", Mechanism: "crlf"},
	}

	allow, err := report.ParseFilter(mechHeader + ",crlf")
	require.NoError(t, err)

	got := report.Apply(findings, allow)
	require.Len(t, got, 2)
	assert.Equal(t, "OR-D01", got[0].TechniqueID)
	assert.Equal(t, "OR-A11", got[1].TechniqueID)

	assert.Equal(t, findings, report.Apply(findings, nil))
}

func TestWrite(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	f := model.NewFinding()
	f.TechniqueID = techA01
	f.Mechanism = mechQuery
	f.Payload = canaryPayload
	f.Repro = "curl -sI https://app.example/a"
	f.Candidate.SourceURL = "https://app.example/a?url=https://allowed.lab/"
	f.Capabilities.RedirectExternal = true
	f.Capabilities.InputControlled = true
	f.Evidence = []string{statusLine}

	require.NoError(t, report.Write(dir, []model.Finding{f}))

	jsonl := readOut(t, dir, "findings.jsonl")

	var row model.Finding
	require.NoError(t, json.Unmarshal([]byte(jsonl), &row))
	assert.Equal(t, techA01, row.TechniqueID)
	assert.Equal(t, "1", row.SchemaVersion)

	raw := readOut(t, dir, "findings.json")

	var all []model.Finding
	require.NoError(t, json.Unmarshal([]byte(raw), &all))
	require.Len(t, all, 1)

	md := readOut(t, dir, "REPORT.md")
	assert.Contains(t, md, "# Open redirects")
	assert.Contains(t, md, techA01)
	assert.Contains(t, md, f.Candidate.SourceURL, "the run report groups by endpoint")
	assert.NotContains(t, md, "\u2014")

	// Every finding also gets a report of its own, ready to submit.
	single := readOut(t, dir, filepath.Join("findings", "OR-A01-"+report.Fingerprint(f)[:8], "REPORT.md"))
	assert.Contains(t, single, "## Proof of concept")
	assert.Contains(t, single, "## Remediation")
	assert.Contains(t, single, techA01)
	assert.NotContains(t, single, "\u2014")
}

// TestWriteManifestListsCurrentFindings proves the manifest names this run's
// finding directories, so a later run can tell what it is still reproducing
// without re-deriving fingerprints itself.
func TestWriteManifestListsCurrentFindings(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	f := model.NewFinding()
	f.TechniqueID = techA01
	f.Mechanism = mechQuery
	f.Payload = canaryPayload
	f.Candidate.SourceURL = "https://app.example/a?url=https://allowed.lab/"
	f.Capabilities.InputControlled = true
	f.Evidence = []string{statusLine}

	require.NoError(t, report.Write(dir, []model.Finding{f}))

	manifest := readOut(t, dir, filepath.Join("findings", "MANIFEST.json"))
	assert.Contains(t, manifest, techA01)
	assert.Contains(t, manifest, report.Fingerprint(f))
}

// TestWriteMarksDirectoriesStaleWhenNotReproduced proves a rerun that no
// longer finds something flags the old directory rather than deleting or
// silently ignoring it.
func TestWriteMarksDirectoriesStaleWhenNotReproduced(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	first := model.NewFinding()
	first.TechniqueID = techA01
	first.Mechanism = mechQuery
	first.Payload = canaryPayload
	first.Candidate.SourceURL = "https://app.example/a?url=https://allowed.lab/"
	first.Capabilities.InputControlled = true
	first.Evidence = []string{statusLine}

	require.NoError(t, report.Write(dir, []model.Finding{first}))

	firstDir := "OR-A01-" + report.Fingerprint(first)[:8]
	_, err := os.Stat(filepath.Join(dir, "findings", firstDir, "STALE.md"))
	require.Error(t, err, "a finding still being reproduced must not be marked stale")

	second := model.NewFinding()
	second.TechniqueID = "OR-A02"
	second.Mechanism = mechQuery
	second.Payload = canaryPayload
	second.Candidate.SourceURL = "https://app.example/b?url=https://allowed.lab/"
	second.Capabilities.InputControlled = true
	second.Evidence = []string{statusLine}

	require.NoError(t, report.Write(dir, []model.Finding{second}))

	stale := readOut(t, dir, filepath.Join("findings", firstDir, "STALE.md"))
	assert.Contains(t, stale, "not reproduced")

	report2 := readOut(t, dir, filepath.Join("findings", "OR-A01-"+report.Fingerprint(first)[:8], "REPORT.md"))
	assert.Contains(t, report2, techA01, "the original report must still be there, not deleted")
}

func readOut(t *testing.T, dir, name string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // G304: dir is t.TempDir output we wrote.
	require.NoError(t, err)

	return string(data)
}

func TestWriteEmptyDirRejected(t *testing.T) {
	t.Parallel()

	err := report.Write("", nil)
	require.Error(t, err)
}

// TestFindingsJSONCarriesRootCause keeps the machine format useful: a reader
// needs to know which defect a finding belongs to without re-deriving it.
func TestFindingsJSONCarriesRootCause(t *testing.T) {
	t.Parallel()

	f := model.NewFinding()
	f.TechniqueID = techA01
	f.Candidate.SourceURL = "https://app.example/r?url=x"
	f.Candidate.ParamName = paramURL

	dir := t.TempDir()
	require.NoError(t, report.WriteVersion(dir, []model.Finding{f}, "test"))

	raw, err := os.ReadFile(filepath.Join(dir, "findings.json")) //nolint:gosec // G304: dir is t.TempDir().
	require.NoError(t, err)

	var out []map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	require.Len(t, out, 1)

	assert.Equal(t, techA01, out[0]["technique_id"])
	assert.NotEmpty(t, out[0]["root_cause"])
	assert.NotEmpty(t, out[0]["fingerprint"])
}
