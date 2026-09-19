package cli_test

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nedlir/detour/internal/cli"
	"github.com/nedlir/detour/internal/lab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttackCommandJSONL(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	list := filepath.Join(t.TempDir(), "urls.txt")
	require.NoError(t, os.WriteFile(list, []byte(srv.URL+"/a01?url=https://allowed.lab/\n"), 0o600))

	cmd := cli.NewRoot()
	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)

	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs([]string{"--rate", "50", "attack", list})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), `"technique_id"`)
	assert.Contains(t, errOut.String(), "findings")
}
