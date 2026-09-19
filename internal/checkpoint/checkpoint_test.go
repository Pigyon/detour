package checkpoint_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nedlir/detour/internal/checkpoint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "run.ckpt")
	store, err := checkpoint.Open(path)
	require.NoError(t, err)

	require.NoError(t, store.RecordAttempt("https://a.example/", "https://canary.invalid", "OR-A07", true))
	require.NoError(t, store.RecordAttempt("https://a.example/", "https://canary.invalid", "OR-A07", true))
	assert.True(t, store.Seen("https://a.example/", "https://canary.invalid", "OR-A07"))
	assert.False(t, store.Seen("https://a.example/", "other", "OR-A07"))
	require.NoError(t, store.Close())

	again, err := checkpoint.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = again.Close() })
	assert.True(t, again.Seen("https://a.example/", "https://canary.invalid", "OR-A07"))
}

func TestLoadSkipsJunk(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "junk.ckpt")
	raw := "{\"schema_version\":\"1\",\"source\":\"https://a.example/\",\"payload\":\"p\",\"technique\":\"OR-A01\",\"hit\":true}\n" +
		"{not json\n" +
		"\n"
	require.NoError(t, os.WriteFile(path, []byte(raw), 0o600))

	store, err := checkpoint.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	assert.True(t, store.Seen("https://a.example/", "p", "OR-A01"))
}

func TestOpenMissingFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "missing.ckpt")
	store, err := checkpoint.Open(path)
	require.NoError(t, err)
	require.NoError(t, store.Close())

	_, err = os.Stat(path)
	require.NoError(t, err)
}

func FuzzLoad(f *testing.F) {
	f.Add("{\"schema_version\":\"1\",\"source\":\"https://a.example/\",\"payload\":\"p\",\"technique\":\"OR-A01\",\"hit\":false}\n")
	f.Add("{")
	f.Add("")

	f.Fuzz(func(_ *testing.T, raw string) {
		if len(raw) > 1<<16 {
			return
		}

		_ = checkpoint.Load(strings.NewReader(raw))
	})
}
