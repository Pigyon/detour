package attack_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nedlir/detour/internal/attack"
	"github.com/nedlir/detour/internal/client"
	"github.com/nedlir/detour/internal/config"
	"github.com/nedlir/detour/internal/lab"
	"github.com/nedlir/detour/internal/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newEngine(t *testing.T) (*attack.Engine, *httptest.Server) {
	t.Helper()

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	cfg := config.Config{
		Canary:      "canary.invalid",
		Rate:        100,
		Concurrency: 4,
		Timeout:     3 * time.Second,
	}
	guard := scope.New(cfg.Canary)
	c, err := client.New(cfg, guard)
	require.NoError(t, err)

	return attack.New(c, cfg.Canary, "", cfg.Concurrency, nil), srv
}

func TestAttackFindsA01(t *testing.T) {
	t.Parallel()

	eng, srv := newEngine(t)
	findings, err := eng.Run(
		context.Background(),
		[]string{srv.URL + "/a01?url=https://allowed.lab/"},
	)
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	ids := map[string]struct{}{}
	for _, f := range findings {
		ids[f.TechniqueID] = struct{}{}
		assert.True(t, f.Capabilities.InputControlled)
		assert.True(t, f.Capabilities.RedirectExternal)
		assert.Equal(t, "1", f.SchemaVersion)
	}

	assert.Contains(t, ids, "OR-A01")
}

func TestAttackKeyword(t *testing.T) {
	t.Parallel()

	eng, srv := newEngine(t)
	findings, err := eng.Run(
		context.Background(),
		[]string{srv.URL + "/a07?url=FUZZ"},
	)
	require.NoError(t, err)
	require.NotEmpty(t, findings)
}

func TestAttackHeaderD01(t *testing.T) {
	t.Parallel()

	eng, srv := newEngine(t)
	findings, err := eng.Run(context.Background(), []string{srv.URL + "/d01"})
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	found := false

	for _, f := range findings {
		if f.TechniqueID == "OR-D01" {
			found = true
		}
	}

	assert.True(t, found)
}

func TestAttackDecoyAllowlistZeroFP(t *testing.T) {
	t.Parallel()

	eng, srv := newEngine(t)
	findings, err := eng.Run(
		context.Background(),
		[]string{srv.URL + "/decoy/allowlist?backUrl=https://allowed.lab/home"},
	)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestAltCanary(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "canary2.invalid", attack.AltCanary("canary.invalid"))
	assert.Equal(t, "x2", attack.AltCanary("x"))
}
