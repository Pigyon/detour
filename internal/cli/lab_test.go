package cli_test

import (
	"bytes"
	"testing"

	"github.com/nedlir/detour/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLabList(t *testing.T) {
	t.Parallel()

	cmd := cli.NewRoot()
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"lab", "--list"})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "OR-A01")
	assert.Contains(t, out.String(), "decoy")
	assert.Contains(t, out.String(), "/landed")
}
