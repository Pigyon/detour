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
	cmd.SetArgs(attackArgs(list))

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), `"technique_id"`)
	assert.Contains(t, errOut.String(), "findings")
}

func TestAttackCommandHAR(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	har := `{"log":{"entries":[{"request":{"url":"` + srv.URL + `/a01?url=https://allowed.lab/"}}]}}`
	path := filepath.Join(t.TempDir(), "run.har")
	require.NoError(t, os.WriteFile(path, []byte(har), 0o600))

	cmd := cli.NewRoot()
	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)

	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs(attackArgs(path))

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), `"technique_id"`)
	assert.Contains(t, errOut.String(), "findings")
}

func TestAttackCommandFilterAndOut(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	list := filepath.Join(t.TempDir(), "urls.txt")
	body := srv.URL + "/a01?url=https://allowed.lab/\n" + srv.URL + "/d01\n"
	require.NoError(t, os.WriteFile(list, []byte(body), 0o600))

	outDir := filepath.Join(t.TempDir(), "out")
	cmd := cli.NewRoot()
	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)

	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs(attackArgs("--filter", "header", "--out", outDir, list))

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), `"OR-D01"`)
	assert.NotContains(t, out.String(), `"OR-A01"`)

	md, err := os.ReadFile(filepath.Join(outDir, "report.md")) //nolint:gosec // G304: outDir is t.TempDir output we wrote.
	require.NoError(t, err)
	assert.Contains(t, string(md), "OR-D01")
	assert.NotContains(t, string(md), "OR-A01")
}

func TestAttackCommandResume(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	list := filepath.Join(t.TempDir(), "urls.txt")
	require.NoError(t, os.WriteFile(list, []byte(srv.URL+"/a01?url=https://allowed.lab/\n"), 0o600))

	ckpt := filepath.Join(t.TempDir(), "run.ckpt")

	run := func() string {
		cmd := cli.NewRoot()
		out := new(bytes.Buffer)
		errOut := new(bytes.Buffer)

		cmd.SetOut(out)
		cmd.SetErr(errOut)
		cmd.SetArgs(attackArgs("--resume", ckpt, list))
		require.NoError(t, cmd.Execute())

		return errOut.String()
	}

	assert.NotEqual(t, "0 findings\n", run())
	assert.Equal(t, "0 findings\n", run())
}

func attackArgs(extra ...string) []string {
	return append([]string{flagRate, "50", "attack"}, extra...)
}
