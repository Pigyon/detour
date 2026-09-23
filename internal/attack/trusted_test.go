package attack_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nedlir/detour/internal/attack"
	"github.com/nedlir/detour/internal/client"
	"github.com/nedlir/detour/internal/config"
	"github.com/nedlir/detour/internal/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allowlistServer only redirects to a destination whose authority starts with
// the one host it trusts, which is the shape a prefix allowlist has.
func allowlistServer(t *testing.T, trusted string) (*attack.Engine, *httptest.Server) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("next")
		if value == "" || !strings.HasPrefix(value, "https://"+trusted) {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		w.Header().Set("Location", value)
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	cfg := config.Config{Canary: testCanary, Rate: 300, Concurrency: 4, Timeout: 3 * time.Second}
	c, err := client.New(cfg, scope.New(cfg.Canary))
	require.NoError(t, err)

	return attack.New(c, cfg.Canary, "", cfg.Concurrency, nil), srv
}

// TestAllowlistBypassWithARealisticSeed is the regression for the miss that
// mattered most: an archived URL essentially never carries the allowlisted
// host, and guessing it from the seed made the whole family silently fail.
func TestAllowlistBypassWithARealisticSeed(t *testing.T) {
	t.Parallel()

	const trusted = "allowed.example"

	eng, srv := allowlistServer(t, trusted)
	eng.SetTrustedHosts([]string{trusted})

	// The seed is what an archive actually returns: a relative path.
	findings, err := eng.Run(context.Background(), []string{srv.URL + "/go?next=/account"})
	require.NoError(t, err)
	assert.NotEmpty(t, findings, "the allowlisted host came from the js stage, not the seed")
}

func TestAllowlistBypassStillWorksFromTheSeed(t *testing.T) {
	t.Parallel()

	const trusted = "allowed.example"

	eng, srv := allowlistServer(t, trusted)

	findings, err := eng.Run(context.Background(), []string{srv.URL + "/go?next=https://" + trusted + "/home"})
	require.NoError(t, err)
	assert.NotEmpty(t, findings)
}
