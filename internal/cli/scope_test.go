package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/nedlir/detour/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScopeTestCommand(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "scope.txt")
	require.NoError(t, os.WriteFile(path, []byte("example.com\n"), 0o600))

	tests := []struct {
		name      string
		url       string
		want      string
		wantError bool
	}{
		{name: "in scope", url: "https://example.com/x", want: "IN-SCOPE"},
		{name: "out of scope", url: "https://evil.com/", want: "OUT-OF-SCOPE", wantError: true},
		{name: "canary", url: "https://canary.invalid/", want: "CANARY", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd := cli.NewRoot()
			out := new(bytes.Buffer)
			cmd.SetOut(out)
			cmd.SetErr(new(bytes.Buffer))
			cmd.SetArgs([]string{"--scope-file", path, "scope", "test", tt.url})

			err := cmd.Execute()

			assert.Contains(t, out.String(), tt.want)

			if tt.wantError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}
