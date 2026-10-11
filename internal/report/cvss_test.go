package report_test

import (
	"testing"

	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/report"
	"github.com/stretchr/testify/assert"
)

// TestSuggestSeverityBaseline pins the bare-redirect score to NVD's own
// published convention for CWE-601, so a drift in the formula or the
// baseline metrics is caught immediately rather than at submission time.
func TestSuggestSeverityBaseline(t *testing.T) {
	t.Parallel()

	got := report.SuggestSeverity(model.NewCapabilitySet())

	assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", got.Vector)
	assert.InDelta(t, 6.1, got.Score, 1e-9)
	assert.Equal(t, "medium", got.Rating)
}

// TestSuggestSeverityEscalations is the capability-to-CVSS derivation table
// IMPLEMENTATION.md's reporting milestone calls for: every escalation
// capability must raise the score, never lower it below the baseline.
func TestSuggestSeverityEscalations(t *testing.T) {
	t.Parallel()

	baseline := report.SuggestSeverity(model.NewCapabilitySet()).Score

	tests := []struct {
		name       string
		caps       model.CapabilitySet
		wantVector string
		wantScore  float64
		wantRating string
	}{
		{
			name:       "oauth redirect_uri token theft",
			caps:       model.CapabilitySet{OAuthRedirectURI: true},
			wantVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
			wantScore:  8.2,
			wantRating: "high",
		},
		{
			name:       "saml relaystate scores the same as oauth",
			caps:       model.CapabilitySet{SAMLRelayState: true},
			wantVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
			wantScore:  8.2,
			wantRating: "high",
		},
		{
			name:       "ssrf chain needs no victim at all",
			caps:       model.CapabilitySet{SSRFChain: true},
			wantVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
			wantScore:  9.3,
			wantRating: "critical",
		},
		{
			name:       "javascript scheme is full script execution",
			caps:       model.CapabilitySet{JavaScriptScheme: true},
			wantVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
			wantScore:  9.3,
			wantRating: "critical",
		},
		{
			name:       "data scheme scores the same as javascript scheme",
			caps:       model.CapabilitySet{DataScheme: true},
			wantVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
			wantScore:  9.3,
			wantRating: "critical",
		},
		{
			name:       "referer leak is a full confidentiality loss",
			caps:       model.CapabilitySet{RefererLeak: true},
			wantVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
			wantScore:  8.2,
			wantRating: "high",
		},
		{
			name:       "a multi-hop chain raises attack complexity",
			caps:       model.CapabilitySet{OAuthRedirectURI: true, HopCount: 2},
			wantVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N",
			wantScore:  6.9,
			wantRating: "medium",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := report.SuggestSeverity(tt.caps)

			assert.Equal(t, tt.wantVector, got.Vector)
			assert.InDelta(t, tt.wantScore, got.Score, 1e-9)
			assert.Equal(t, tt.wantRating, got.Rating)
			assert.GreaterOrEqual(t, got.Score, baseline,
				"an escalation capability must never score below the bare-redirect baseline")
		})
	}
}

// TestSuggestSeverityNeverDecreasesOnMultipleCapabilities proves combining
// capabilities only ever raises a component, matching how CapabilitySet
// itself only ever accumulates on Merge.
func TestSuggestSeverityNeverDecreasesOnMultipleCapabilities(t *testing.T) {
	t.Parallel()

	single := report.SuggestSeverity(model.CapabilitySet{OAuthRedirectURI: true}).Score
	combined := report.SuggestSeverity(model.CapabilitySet{
		OAuthRedirectURI: true,
		CSRFReferer:      true,
		CachePoisoned:    true,
	}).Score

	assert.GreaterOrEqual(t, combined, single)
}
