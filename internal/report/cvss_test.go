package report_test

import (
	"strings"
	"testing"

	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/report"
	"github.com/stretchr/testify/assert"
)

func TestDeriveSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		caps model.CapabilitySet
		want string
	}{
		{
			name: "nothing proven scores nothing",
			caps: model.CapabilitySet{},
			want: report.SeverityNone,
		},
		{
			name: "a candidate that has not shown a redirect scores nothing",
			caps: model.CapabilitySet{InputControlled: true},
			want: report.SeverityNone,
		},
		{
			name: "a bare confirmed redirect is low",
			caps: model.CapabilitySet{RedirectExternal: true, InputControlled: true},
			want: report.SeverityLow,
		},
		{
			name: "browser confirmed is still low on its own",
			caps: model.CapabilitySet{RedirectExternal: true, InputControlled: true, BrowserConfirmed: true},
			want: report.SeverityMedium,
		},
		{
			name: "oauth redirect_uri is the paid one",
			caps: model.CapabilitySet{RedirectExternal: true, InputControlled: true, OAuthRedirectURI: true},
			want: report.SeverityHigh,
		},
		{
			name: "javascript scheme is script execution",
			caps: model.CapabilitySet{RedirectExternal: true, InputControlled: true, JavaScriptScheme: true},
			want: report.SeverityHigh,
		},
		{
			name: "oauth plus browser proof is critical",
			caps: model.CapabilitySet{
				RedirectExternal: true, InputControlled: true,
				BrowserConfirmed: true, OAuthRedirectURI: true, PhishingVector: true,
			},
			want: report.SeverityCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := report.Derive(tt.caps)
			assert.Equal(t, tt.want, got.Severity, "base %.1f from %v", got.Base, got.Because)
			assert.LessOrEqual(t, got.Base, 10.0)
			assert.True(t, strings.HasPrefix(got.CVSS31, "CVSS:3.1/"), got.CVSS31)
			assert.True(t, strings.HasPrefix(got.CVSS40, "CVSS:4.0/"), got.CVSS40)
		})
	}
}

// TestDeriveIsExplained keeps the number from being a bare assertion: every
// score names the capabilities it came from.
func TestDeriveIsExplained(t *testing.T) {
	t.Parallel()

	got := report.Derive(model.CapabilitySet{
		RedirectExternal: true, InputControlled: true, OAuthRedirectURI: true,
	})

	assert.Contains(t, got.Because, "redirect.external")
	assert.Contains(t, got.Because, "oauth.redirect_uri")
}
