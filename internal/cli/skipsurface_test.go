package cli

import (
	"testing"

	"github.com/nedlir/detour/internal/config"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// TestSurfaceOriginsSkipped checks that --skip-surface short-circuits before
// the mapper is built, so no enumeration (and no network, no hang) happens.
func TestSurfaceOriginsSkipped(t *testing.T) {
	t.Parallel()

	got := surfaceOrigins(&cobra.Command{}, config.Config{}, "example.com", &reconFlags{skipSurface: true})
	assert.Nil(t, got)
}

// TestSurfaceOriginsPassiveSkipped is the sibling: --passive also skips the
// surface stage entirely.
func TestSurfaceOriginsPassiveSkipped(t *testing.T) {
	t.Parallel()

	got := surfaceOrigins(&cobra.Command{}, config.Config{}, "example.com", &reconFlags{passive: true})
	assert.Nil(t, got)
}
