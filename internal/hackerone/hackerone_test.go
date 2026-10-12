package hackerone_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nedlir/detour/internal/hackerone"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixture is a trimmed, real-shaped response: no top-level "data" envelope,
// attributes and relationships at the root, matching what the hacker API's
// program endpoint actually returns.
const fixture = `{
	"attributes": {"handle": "acme", "name": "Acme"},
	"relationships": {
		"structured_scopes": {
			"data": [
				{"attributes": {"asset_identifier": "acme.com", "asset_type": "URL",
					"eligible_for_submission": true, "eligible_for_bounty": true}},
				{"attributes": {"asset_identifier": "*.acme.com", "asset_type": "WILDCARD",
					"eligible_for_submission": true, "eligible_for_bounty": true}},
				{"attributes": {"asset_identifier": "com.acme.app", "asset_type": "GOOGLE_PLAY_APP_ID",
					"eligible_for_submission": true, "eligible_for_bounty": true}},
				{"attributes": {"asset_identifier": "legacy.acme.com", "asset_type": "URL",
					"eligible_for_submission": false, "eligible_for_bounty": false}}
			]
		}
	}
}`

// withServer points the package-level APIBase at a local stand-in and
// restores it on cleanup. Every test using it mutates shared state, so none
// of them may run in parallel with another.
func withServer(t *testing.T, handler http.HandlerFunc) {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	previous := hackerone.APIBase
	hackerone.APIBase = srv.URL

	t.Cleanup(func() { hackerone.APIBase = previous })
}

//nolint:paralleltest // withServer mutates the shared package-level APIBase var
func TestFetchScopeParsesStructuredScopes(t *testing.T) {
	withServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/acme", r.URL.Path)

		_, _ = w.Write([]byte(fixture))
	})

	assets, err := hackerone.FetchScope(context.Background(), "acme", "user", "token")
	require.NoError(t, err)
	assert.Len(t, assets, 4)
}

//nolint:paralleltest // withServer mutates the shared package-level APIBase var
func TestFetchScopeSendsBasicAuth(t *testing.T) {
	var gotAuth string

	withServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(fixture))
	})

	_, err := hackerone.FetchScope(context.Background(), "acme", "nedlir", "secret-token")
	require.NoError(t, err)

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("nedlir:secret-token"))
	assert.Equal(t, want, gotAuth)
}

//nolint:paralleltest // withServer mutates the shared package-level APIBase var
func TestFetchScopeUnauthorized(t *testing.T) {
	withServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	_, err := hackerone.FetchScope(context.Background(), "acme", "user", "bad-token")
	require.ErrorIs(t, err, hackerone.ErrUnauthorized)
}

// TestScopeLinesKeepsOnlySubmittableWebAssets proves the hard boundary: a
// non-submittable asset is never emitted even if it offers a bounty, and a
// mobile store listing is dropped because there is no web surface to scan.
func TestScopeLinesKeepsOnlySubmittableWebAssets(t *testing.T) {
	t.Parallel()

	assets := []hackerone.Asset{
		{Identifier: "acme.com", Type: "URL", EligibleForSubmission: true, EligibleForBounty: true},
		{Identifier: "*.acme.com", Type: "WILDCARD", EligibleForSubmission: true, EligibleForBounty: true},
		{Identifier: "com.acme.app", Type: "GOOGLE_PLAY_APP_ID", EligibleForSubmission: true, EligibleForBounty: true},
		{Identifier: "legacy.acme.com", Type: "URL", EligibleForSubmission: false, EligibleForBounty: false},
	}

	got := hackerone.ScopeLines(assets)

	assert.Equal(t, []string{"acme.com", "*.acme.com"}, got)
}

func TestScopeLinesEmptyOnNoAssets(t *testing.T) {
	t.Parallel()

	got := hackerone.ScopeLines(nil)
	assert.Empty(t, got)
}
