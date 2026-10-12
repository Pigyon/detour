package report_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nedlir/detour/internal/lab"
	"github.com/nedlir/detour/internal/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWriteOpaqueEnvelopesDecodesTheBreakdown proves a human reviewing the
// output directory gets the full layer breakdown of a resisted envelope
// without having to rerun detour decode by hand.
func TestWriteOpaqueEnvelopesDecodesTheBreakdown(t *testing.T) {
	t.Parallel()

	blob, err := lab.EncodeClick("https://" + lab.AllowedHost + "/home")
	require.NoError(t, err)

	source := "https://site.lab/track/click2/" + blob + ".html"
	dir := t.TempDir()

	require.NoError(t, report.WriteOpaqueEnvelopes(dir, []string{source}))

	raw := readOut(t, dir, "opaque_envelopes.json")
	assert.Contains(t, raw, source)
	assert.Contains(t, raw, lab.AllowedHost, "the decoded destination must be visible in the breakdown")
	assert.Contains(t, raw, `"layers"`)
}

// TestWriteOpaqueEnvelopesEmptyWritesNothing proves a target with no
// resisted envelope gets no file at all, rather than one that says "none"
// and looks identical to a target that was never checked.
func TestWriteOpaqueEnvelopesEmptyWritesNothing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	require.NoError(t, report.WriteOpaqueEnvelopes(dir, nil))

	_, err := os.Stat(filepath.Join(dir, "opaque_envelopes.json"))
	assert.True(t, os.IsNotExist(err), "no envelopes must mean no file")
}

// TestWriteOpaqueEnvelopesSkipsUnopenableSources proves a source that no
// longer decodes (or never did) is skipped rather than failing the whole
// write, since Coverage.OpaqueEnvelopes is itself a best-effort list.
func TestWriteOpaqueEnvelopesSkipsUnopenableSources(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	require.NoError(t, report.WriteOpaqueEnvelopes(dir, []string{"https://site.lab/plain"}))

	raw := readOut(t, dir, "opaque_envelopes.json")
	assert.Equal(t, "[]\n", raw)
}
