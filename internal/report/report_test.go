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
	mechHeader = "header"
	techA01    = "OR-A01"
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
		{name: "list", in: mechHeader + ", crlf,query", want: []string{"crlf", mechHeader, "query"}},
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
		{TechniqueID: techA01, Mechanism: "query"},
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
	f.Mechanism = "query"
	f.Payload = "https://canary.invalid"
	f.Repro = "curl -sI https://app.example/a"
	f.Candidate.SourceURL = "https://app.example/a?url=https://allowed.lab/"
	f.Capabilities.RedirectExternal = true
	f.Capabilities.InputControlled = true
	f.Evidence = []string{"status 302"}

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

	md := readOut(t, dir, "report.md")
	assert.Contains(t, md, "# detour findings")
	assert.Contains(t, md, techA01)
	assert.Contains(t, md, "input_controlled")
	assert.NotContains(t, md, "\u2014")
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
