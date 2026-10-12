package confirm_test

import (
	"testing"

	"github.com/nedlir/detour/internal/confirm"
	"github.com/stretchr/testify/assert"
)

// TestInjectionCandidatesKeepsRequestedQueryURLs proves the crawl mines the
// browser's request chain for the right thing: in-scope URLs that were
// actually requested and carry a query parameter, which is where an open
// redirect hides. Blocked intents, parameterless paths, and non-http schemes
// are not injection points.
func TestInjectionCandidatesKeepsRequestedQueryURLs(t *testing.T) {
	t.Parallel()

	chain := []confirm.Hop{
		{URL: "https://site.test/go?returnUrl=/home", Kind: confirm.HopRequest},
		{URL: "https://site.test/app#/route", Kind: confirm.HopFrame},       // no query
		{URL: "https://api.site.test/v1/profile", Kind: confirm.HopRequest}, // no query
		{URL: "https://evil.test/steal?x=1", Kind: confirm.HopBlocked},      // blocked intent
		{URL: "https://api.site.test/track?redirect=https://x", Kind: confirm.HopRequest},
		{URL: "data:text/html,<a>", Kind: confirm.HopRequest}, // non-http
	}

	got := confirm.InjectionCandidates(chain)

	assert.Equal(t, []string{
		"https://site.test/go?returnUrl=/home",
		"https://api.site.test/track?redirect=https://x",
	}, got)
}

// TestInjectionCandidatesEmptyChain proves a chain with nothing worth
// attacking yields an empty slice, not nil surprises downstream.
func TestInjectionCandidatesEmptyChain(t *testing.T) {
	t.Parallel()

	assert.Empty(t, confirm.InjectionCandidates(nil))
}
