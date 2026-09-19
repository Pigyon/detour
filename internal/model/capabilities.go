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
	out.RedirectExternal = c.RedirectExternal || other.RedirectExternal
	out.BrowserConfirmed = c.BrowserConfirmed || other.BrowserConfirmed
	out.InputControlled = c.InputControlled || other.InputControlled
	out.JavaScriptScheme = c.JavaScriptScheme || other.JavaScriptScheme
	out.SSRFChain = c.SSRFChain || other.SSRFChain
	out.RefererLeak = c.RefererLeak || other.RefererLeak
	out.OAuthRedirectURI = c.OAuthRedirectURI || other.OAuthRedirectURI

	if other.HopCount > out.HopCount {
		out.HopCount = other.HopCount
	}

	return out
}
