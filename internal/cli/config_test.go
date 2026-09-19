package cli_test

import (
	"bytes"
	"testing"

	"github.com/nedlir/detour/internal/cli"
	"github.com/nedlir/detour/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanaryFlagOverridesDefault(t *testing.T) {
	t.Parallel()

	cmd := cli.NewRoot()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"--canary", "flag.invalid", "version"})

	require.NoError(t, cmd.Execute())

	cfg, ok := config.FromContext(cmd.Context())
	require.True(t, ok)
	assert.Equal(t, "flag.invalid", cfg.Canary)
}
