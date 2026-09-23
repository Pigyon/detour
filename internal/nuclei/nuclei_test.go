package nuclei_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nedlir/detour/internal/nuclei"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunWithoutNucleiIsACleanNoOp is the contract: nuclei is optional, so its
// absence must not fail a run or produce a finding.
func TestRunWithoutNucleiIsACleanNoOp(t *testing.T) {
	t.Parallel()

	found, err := nuclei.Run(context.Background(),
		nuclei.Options{Binary: "definitely-not-installed-detour"},
		[]string{"https://app.example/r?url=x"})

	require.ErrorIs(t, err, nuclei.ErrNotInstalled)
	assert.Empty(t, found)
}

func TestFindReportsAMissingBinary(t *testing.T) {
	t.Parallel()

	_, err := nuclei.Find(nuclei.Options{Binary: "definitely-not-installed-detour"})
	require.ErrorIs(t, err, nuclei.ErrNotInstalled)
}

// TestRunReadsResults drives a stub that speaks nuclei's jsonl, so the parsing
// is covered without requiring the real binary.
func TestRunReadsResults(t *testing.T) {
	t.Parallel()

	stub := writeStub(t, `{"template-id":"open-redirect","matched-at":"https://app.example/r?url=//evil","info":{"name":"Open Redirect"}}
not json
{"template-id":"","matched-at":"https://app.example/x"}
{"template-id":"generic-redirect","host":"app.example","info":{"name":"Generic"}}
`)

	found, err := nuclei.Run(context.Background(),
		nuclei.Options{Binary: stub},
		[]string{"https://app.example/r?url=x"})
	require.NoError(t, err)
	require.Len(t, found, 2, "malformed and id-less lines are skipped")

	assert.Equal(t, "nuclei", found[0].Mechanism)
	assert.Equal(t, "https://app.example/r?url=//evil", found[0].ProbeURL)
	assert.Contains(t, found[0].Rationale, "detour did not verify")
	assert.Contains(t, found[0].Evidence, "nuclei_template=open-redirect")

	// A result with no matched-at falls back to the host.
	assert.Equal(t, "app.example", found[1].ProbeURL)
}

func TestRunWithNoURLsDoesNothing(t *testing.T) {
	t.Parallel()

	found, err := nuclei.Run(context.Background(), nuclei.Options{Binary: writeStub(t, "")}, nil)
	require.NoError(t, err)
	assert.Empty(t, found)
}

// writeStub creates an executable that prints the given jsonl.
func writeStub(t *testing.T, output string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "nuclei")

	script := "#!/bin/sh\ncat <<'DETOUR_EOF'\n" + output + "DETOUR_EOF\n"
	require.NoError(t, os.WriteFile(path, []byte(script), 0o700)) //nolint:gosec // G306: a test stub must be executable.

	return path
}
