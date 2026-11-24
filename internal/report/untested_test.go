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

// TestWriteUntestedRoundTrips proves untested.json carries the exact count,
// the vendor tally, the refused probes and the walled sources.
func TestWriteUntestedRoundTrips(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	in := report.Untested{
		Blocked:       3,
		BlockedBy:     map[string]int{"cloudflare": 2, "unknown": 1},
		BlockedProbes: []model.BlockedProbe{{URL: "https://a.test/go?url=x", Status: 403, Vendor: "cloudflare"}},
		AuthWalls: []model.AuthWall{{
			URL: "https://a.test/account?next=/", Status: 302, Reason: "login redirect", Location: "/login",
		}},
	}

	require.NoError(t, report.WriteUntested(dir, in))

	raw, err := os.ReadFile(filepath.Join(dir, "untested.json")) //nolint:gosec // G304: dir is t.TempDir output.
	require.NoError(t, err)

	var out report.Untested
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, in, out)
}

// TestWriteUntestedEmptyWritesNothing keeps a clean run's output directory
// free of a file that would only say there is nothing in it.
func TestWriteUntestedEmptyWritesNothing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, report.WriteUntested(dir, report.Untested{}))

	_, err := os.Stat(filepath.Join(dir, "untested.json"))
	assert.True(t, os.IsNotExist(err))
}
