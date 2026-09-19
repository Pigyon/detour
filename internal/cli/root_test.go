package cli_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nedlir/detour/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionCommand(t *testing.T) {
	t.Parallel()

	cmd := cli.NewRoot()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"version"})

	require.NoError(t, cmd.Execute())
	assert.True(t, strings.HasPrefix(buf.String(), "detour "))
	assert.Contains(t, buf.String(), "go:")
}

func TestVersionFlag(t *testing.T) {
	t.Parallel()

	cmd := cli.NewRoot()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"--version"})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, buf.String(), "dev")
}

func TestRootHelp(t *testing.T) {
	t.Parallel()

	cmd := cli.NewRoot()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"--help"})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, buf.String(), "detour")
	assert.Contains(t, buf.String(), "scope")
	assert.Contains(t, buf.String(), "lab")
	assert.Contains(t, buf.String(), "--canary")
	assert.Contains(t, buf.String(), "--scope-file")
}
