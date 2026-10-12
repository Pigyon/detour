package cli_test

import (
	"path/filepath"
	"testing"

	"github.com/nedlir/detour/internal/cli"
	"github.com/stretchr/testify/assert"
)

// TestTargetOutDirIsolatesEachTarget proves a multi-target sweep writes each
// target into its own subdirectory of --out so one report never overwrites
// the next, and that no --out stays no --out.
func TestTargetOutDirIsolatesEachTarget(t *testing.T) {
	t.Parallel()

	a := cli.TargetOutDir("/out", "www.rockstargames.com")
	b := cli.TargetOutDir("/out", "rockstarnorth.com")

	assert.NotEqual(t, a, b, "two apexes must not share an output directory")
	assert.Equal(t, "/out", filepath.Dir(a))
	assert.Equal(t, "/out", filepath.Dir(b))
	assert.Empty(t, cli.TargetOutDir("", "www.rockstargames.com"),
		"with no --out nothing is written to disk")
}
