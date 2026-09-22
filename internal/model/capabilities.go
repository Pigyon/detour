package model

// CapabilitySet is the proven-fact model for a finding. CVSS is derived from
// these flags at report time and is never asserted directly.
type CapabilitySet struct {
	RedirectExternal bool `json:"redirect.external"`
	BrowserConfirmed bool `json:"browser_confirmed"`
	HopCount         int  `json:"hop_count"`
	InputControlled  bool `json:"input_controlled"`
	JavaScriptScheme bool `json:"javascript_scheme"`
	SSRFChain        bool `json:"ssrf_chain"`
	RefererLeak      bool `json:"referer_leak"`
	OAuthRedirectURI bool `json:"oauth.redirect_uri"`

	// Escalation capabilities. Each names something that turns a bare
	// redirect into a higher-impact finding. They are facts about shape and
	// position, never the result of performing the escalation.
	PostLogoutRedirect bool `json:"oidc.post_logout_redirect_uri,omitempty"`
	SAMLRelayState     bool `json:"saml.relaystate,omitempty"`
	DataScheme         bool `json:"data_scheme,omitempty"`
	CSPBypass          bool `json:"csp_bypass,omitempty"`
	CSRFReferer        bool `json:"csrf.referer_bypass,omitempty"`
	CachePoisoned      bool `json:"cache_poisoned,omitempty"`
	CrossProtocol      bool `json:"cross_protocol,omitempty"`
	PhishingVector     bool `json:"phishing_vector,omitempty"`
}

// NewCapabilitySet returns a zero-value capability set.
func NewCapabilitySet() CapabilitySet {
	return CapabilitySet{}
}

// Clone returns a copy of the set.
func (c CapabilitySet) Clone() CapabilitySet {
	return c
}

// Merge overlays other onto c. HopCount takes the larger of the two.
func (c CapabilitySet) Merge(other CapabilitySet) CapabilitySet {
	out := c

	for _, pair := range out.pairs(&other) {
		*pair.into = *pair.into || *pair.from
	}

	if other.HopCount > out.HopCount {
		out.HopCount = other.HopCount
	}

	return out
}

// pairs lines up every boolean capability with its counterpart in other, so
// Merge stays one rule rather than one branch per field.
func (c *CapabilitySet) pairs(other *CapabilitySet) []struct{ into, from *bool } {
	return []struct{ into, from *bool }{
		{&c.RedirectExternal, &other.RedirectExternal},
		{&c.BrowserConfirmed, &other.BrowserConfirmed},
		{&c.InputControlled, &other.InputControlled},
		{&c.JavaScriptScheme, &other.JavaScriptScheme},
		{&c.SSRFChain, &other.SSRFChain},
		{&c.RefererLeak, &other.RefererLeak},
		{&c.OAuthRedirectURI, &other.OAuthRedirectURI},
		{&c.PostLogoutRedirect, &other.PostLogoutRedirect},
		{&c.SAMLRelayState, &other.SAMLRelayState},
		{&c.DataScheme, &other.DataScheme},
		{&c.CSPBypass, &other.CSPBypass},
		{&c.CSRFReferer, &other.CSRFReferer},
		{&c.CachePoisoned, &other.CachePoisoned},
		{&c.CrossProtocol, &other.CrossProtocol},
		{&c.PhishingVector, &other.PhishingVector},
	}
}
