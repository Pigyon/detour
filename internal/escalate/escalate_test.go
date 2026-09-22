package escalate_test

import (
	"testing"

	"github.com/nedlir/detour/internal/escalate"
	"github.com/nedlir/detour/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func finding(technique, source, param, payload string, evidence ...string) model.Finding {
	f := model.NewFinding()
	f.TechniqueID = technique
	f.Payload = payload
	f.Evidence = evidence
	f.Candidate = model.NewNavigationCandidate(source, model.RepresentationQueryParameter)
	f.Candidate.ParamName = param
	f.Capabilities.RedirectExternal = true
	f.Capabilities.InputControlled = true

	return f
}

func TestAnalyzeChains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   model.Finding
		want func(model.CapabilitySet) bool
	}{
		{
			name: "oauth authorize endpoint",
			in:   finding("OR-A09", "https://a.lab/oauth/authorize?redirect_uri=x", "redirect_uri", "https://c/"),
			want: func(c model.CapabilitySet) bool { return c.OAuthRedirectURI },
		},
		{
			name: "oidc logout",
			in:   finding("OR-A07", "https://a.lab/oidc/logout", "post_logout_redirect_uri", "https://c/"),
			want: func(c model.CapabilitySet) bool { return c.PostLogoutRedirect },
		},
		{
			name: "saml relaystate",
			in:   finding("OR-D04", "https://a.lab/saml/acs", "RelayState", "https://c/"),
			want: func(c model.CapabilitySet) bool { return c.SAMLRelayState },
		},
		{
			name: "javascript scheme",
			in:   finding("OR-E01", "https://a.lab/go", "url", "javascript:alert(1)"),
			want: func(c model.CapabilitySet) bool { return c.JavaScriptScheme },
		},
		{
			name: "data scheme",
			in:   finding("OR-E02", "https://a.lab/go", "url", "data:text/html,x"),
			want: func(c model.CapabilitySet) bool { return c.DataScheme },
		},
		{
			name: "http downgrade is cross protocol",
			in:   finding("OR-E03", "https://a.lab/go", "url", "http://a.lab/"),
			want: func(c model.CapabilitySet) bool { return c.CrossProtocol },
		},
		{
			name: "referer technique",
			in:   finding("OR-D05", "https://a.lab/go", "", "https://c/"),
			want: func(c model.CapabilitySet) bool { return c.RefererLeak },
		},
		{
			name: "same host redirector launders referer",
			in:   finding("OR-F06", "https://a.lab/go", "url", "https://c/"),
			want: func(c model.CapabilitySet) bool { return c.CSRFReferer },
		},
		{
			name: "csp allowlisted host",
			in:   finding("OR-F02", "https://a.lab/csp/redir", "url", "https://c/"),
			want: func(c model.CapabilitySet) bool { return c.CSPBypass },
		},
		{
			name: "server side fetcher",
			in:   finding("OR-F03", "https://a.lab/ssrf/fetch", "url", "https://c/"),
			want: func(c model.CapabilitySet) bool { return c.SSRFChain },
		},
		{
			name: "cacheable response",
			in:   finding("OR-D01", "https://a.lab/go", "", "https://c/", "x-cache: HIT"),
			want: func(c model.CapabilitySet) bool { return c.CachePoisoned },
		},
		{
			name: "login path is a phishing vector",
			in:   finding("OR-A07", "https://a.lab/ucenter/signin", "backUrl", "https://c/"),
			want: func(c model.CapabilitySet) bool { return c.PhishingVector },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := escalate.Analyze(tt.in)
			assert.True(t, tt.want(got.Capabilities), "capability not set: %v", escalate.Names(got.Capabilities))
			assert.Equal(t, got.Capabilities, got.Candidate.Capabilities, "candidate mirrors the set")
		})
	}
}

// TestAnalyzeOnlyAdds pins that escalation never downgrades a finding. Absence
// of an escalation shape is not evidence against the redirect itself.
func TestAnalyzeOnlyAdds(t *testing.T) {
	t.Parallel()

	in := finding("OR-A07", "https://a.lab/plain", "url", "https://c/")
	in.Capabilities.BrowserConfirmed = true

	got := escalate.Analyze(in)

	assert.True(t, got.Capabilities.RedirectExternal)
	assert.True(t, got.Capabilities.InputControlled)
	assert.True(t, got.Capabilities.BrowserConfirmed)
	assert.Equal(t, in.Verdict, got.Verdict)
	assert.Empty(t, escalate.Names(got.Capabilities), "a plain redirect earns no escalation")
}

// TestAnalyzeIsPure is the capability-only guard, expressed the only way that
// actually holds: the stage takes no client and no context, so it has no way
// to issue the internal request or poison the cache it reports on.
//
// The signature is the guarantee. If someone later adds a client parameter,
// this test stops compiling, which is the point.
func TestAnalyzeIsPure(t *testing.T) {
	t.Parallel()

	analyze := escalate.Analyze
	require.NotNil(t, analyze)

	in := finding("OR-F03", "https://a.lab/ssrf/fetch", "url", "https://c/")

	first := escalate.Analyze(in)
	second := escalate.Analyze(in)

	assert.Equal(t, first, second, "analysis is deterministic and side-effect free")
	assert.True(t, first.Capabilities.SSRFChain)
	assert.False(t, first.Capabilities.BrowserConfirmed, "nothing was performed to prove it")
}
