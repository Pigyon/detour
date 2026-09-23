package checkpoint_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nedlir/detour/internal/checkpoint"
	"github.com/nedlir/detour/internal/model"
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
	raw := "{\"schema_version\":\"2\",\"source\":\"https://a.example/\",\"attempt\":\"p\",\"technique\":\"OR-A01\",\"hit\":true}\n" +
		"{not json\n" +
		"\n"
	require.NoError(t, os.WriteFile(path, []byte(raw), 0o600))

	store, err := checkpoint.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	assert.True(t, store.Seen("https://a.example/", "p", "OR-A01"))
}

// TestLoadIgnoresOtherSchemaVersions keeps a v1 file from being read as v2.
//
// A v1 record has no attempt field, so every one of them would key on the
// empty string and the whole scan would look complete after one line.
func TestLoadIgnoresOtherSchemaVersions(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "v1.ckpt")
	raw := "{\"schema_version\":\"1\",\"source\":\"https://a.example/\",\"payload\":\"p\",\"technique\":\"OR-A01\",\"hit\":true}\n"
	require.NoError(t, os.WriteFile(path, []byte(raw), 0o600))

	store, err := checkpoint.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	assert.False(t, store.Seen("https://a.example/", "p", "OR-A01"),
		"a record from another schema version must not be trusted")
	assert.False(t, store.Seen("https://a.example/", "", "OR-A01"),
		"and must not collapse onto the empty attempt")
}

// TestAttemptsWithTheSameTechniqueStayDistinct is the defect this schema
// exists for: one envelope carrying the destination in two fields produced two
// attempts that differed only in the request, and keying without it let the
// first one's miss suppress the second one's hit.
func TestAttemptsWithTheSameTechniqueStayDistinct(t *testing.T) {
	t.Parallel()

	const (
		source = "https://a.example/go"
		tech   = "OR-B01"
	)

	path := filepath.Join(t.TempDir(), "two.ckpt")
	store, err := checkpoint.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	require.NoError(t, store.RecordAttempt(source, source+"?b=1", tech, false))

	assert.False(t, store.Seen(source, source+"?b=2", tech),
		"a different request is a different attempt")

	f := model.NewFinding()
	f.TechniqueID = tech
	require.NoError(t, store.RecordHit(source, source+"?b=2", tech, f))

	recovered, ok := store.Recover(source, source+"?b=2", tech)
	require.True(t, ok)
	assert.Equal(t, tech, recovered.TechniqueID)

	_, ok = store.Recover(source, source+"?b=1", tech)
	assert.False(t, ok, "the attempt that missed still has no finding")
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
	f.Add("{\"schema_version\":\"2\",\"source\":\"https://a.example/\",\"attempt\":\"p\",\"technique\":\"OR-A01\",\"hit\":false}\n")
	f.Add("{\"schema_version\":\"1\",\"source\":\"https://a.example/\",\"payload\":\"p\",\"technique\":\"OR-A01\",\"hit\":false}\n")
	f.Add("{")
	f.Add("")

	f.Fuzz(func(_ *testing.T, raw string) {
		if len(raw) > 1<<16 {
			return
		}

		_, _ = checkpoint.Load(strings.NewReader(raw))
	})
}

// TestRecoverReturnsTheFinding is the regression for a resumed run losing
// everything the interrupted one had proved.
func TestRecoverReturnsTheFinding(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "run.ckpt")

	store, err := checkpoint.Open(path)
	require.NoError(t, err)

	f := model.NewFinding()
	f.TechniqueID = "OR-A01"
	f.Payload = "https://allowed.example@canary.invalid"

	require.NoError(t, store.RecordHit("https://app.example/r", f.Payload, f.TechniqueID, f))
	require.NoError(t, store.RecordAttempt("https://app.example/r", "miss", "OR-A07", false))
	require.NoError(t, store.Close())

	reopened, err := checkpoint.Open(path)
	require.NoError(t, err)

	t.Cleanup(func() { _ = reopened.Close() })

	got, ok := reopened.Recover("https://app.example/r", f.Payload, f.TechniqueID)
	require.True(t, ok, "a recorded hit must come back")
	assert.Equal(t, f.TechniqueID, got.TechniqueID)
	assert.Equal(t, f.Payload, got.Payload)

	// An attempt that found nothing has nothing to hand back.
	_, ok = reopened.Recover("https://app.example/r", "miss", "OR-A07")
	assert.False(t, ok)
}
