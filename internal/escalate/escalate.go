// Package escalate identifies what turns a bare open redirect into something
// worth paying for, and records each one as a capability.
//
// It never performs the escalation. That is enforced by construction rather
// than by discipline: every function here is pure. The package imports no HTTP
// client, takes no context, and has no way to reach the network, so it cannot
// complete an OAuth dance, ask a server-side fetcher to touch an internal
// address, or poison a shared cache even by accident.
package escalate

import (
	"net/url"
	"strings"

	"github.com/nedlir/detour/internal/model"
)

// oauthPaths are the authorization endpoints where a redirect_uri bypass is
// token theft rather than a nuisance.
var oauthPaths = []string{
	"/oauth/authorize", "/oauth2/authorize", "/authorize", "/oauth/auth",
	"/connect/authorize", "/as/authorization.oauth2", "/o/oauth2/auth",
	"/oauth/v2/authorize", "/login/oauth/authorize",
}

// logoutPaths are where post_logout_redirect_uri lives. It is routinely
// unvalidated on endpoints whose login counterpart is not.
var logoutPaths = []string{
	"/logout", "/oidc/logout", "/connect/endsession", "/v2/logout",
	"/protocol/openid-connect/logout", "/signout", "/sign-out",
}

// samlPaths are assertion consumer endpoints, where RelayState is free text.
var samlPaths = []string{"/saml", "/saml2", "/sso/saml", "/acs", "/saml/acs"}

// wsFedPaths are WS-Federation's sign-in endpoints: ADFS and Azure AD's
// equivalent of a SAML assertion consumer, where wreply is the same kind of
// free-text destination RelayState is.
var wsFedPaths = []string{"/adfs/ls", "/wsfed", "/federation", "/_trust/default.aspx"}

// Parameter names that carry each chain's destination.
const (
	paramRedirectURI    = "redirect_uri"
	paramPostLogout     = "post_logout_redirect_uri"
	paramRelayState     = "relaystate"
	paramSAMLRelayState = "SAMLRelayState"
	paramWReply         = "wreply"
)

// Analyze returns f with its escalation capabilities filled in.
//
// It only ever adds capabilities. A finding is never downgraded here, because
// absence of an escalation shape is not evidence against the redirect itself.
func Analyze(f model.Finding) model.Finding {
	caps := f.Capabilities

	parsed, err := url.Parse(f.Candidate.SourceURL)
	if err == nil {
		caps = applyPosition(caps, parsed, f.Candidate.ParamName)
	}

	caps = applyScheme(caps, f.Payload)
	caps = applyTechnique(caps, f.TechniqueID)
	caps = applyEvidence(caps, f.Evidence)

	f.Capabilities = caps
	f.Candidate.Capabilities = caps

	return f
}

// AnalyzeAll runs Analyze over a set of findings.
func AnalyzeAll(findings []model.Finding) []model.Finding {
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		out = append(out, Analyze(f))
	}

	return out
}

// applyPosition reads the endpoint the redirect sits on. Where a redirect
// lives decides most of its impact: the same bypass is Low on a marketing page
// and token theft on an authorize endpoint.
func applyPosition(caps model.CapabilitySet, parsed *url.URL, param string) model.CapabilitySet {
	path := strings.ToLower(parsed.EscapedPath())
	lowerParam := strings.ToLower(param)
	query := parsed.Query()

	caps.OAuthRedirectURI = caps.OAuthRedirectURI ||
		sits(path, oauthPaths, lowerParam, query, paramRedirectURI, paramRedirectURI)
	caps.PostLogoutRedirect = caps.PostLogoutRedirect ||
		sits(path, logoutPaths, lowerParam, query, paramPostLogout, paramPostLogout)
	caps.SAMLRelayState = caps.SAMLRelayState ||
		sits(path, samlPaths, lowerParam, query, paramRelayState, paramSAMLRelayState)
	// WS-Federation's wreply carries the same free-text destination RelayState
	// does. OR-D04 covers SSO generically, not SAML alone, so it shares the
	// capability rather than earning a field of its own.
	caps.SAMLRelayState = caps.SAMLRelayState ||
		sits(path, wsFedPaths, lowerParam, query, paramWReply, paramWReply)
	caps.PhishingVector = caps.PhishingVector || matchesAny(path, authPaths)

	return caps
}

// authPaths are where a victim already expects to authenticate, which is what
// makes a redirect there a first-party phishing vector.
var authPaths = []string{"login", "signin", "sign-in", "account", "auth"}

// sits reports whether a finding is positioned on one of these endpoints,
// either by path, by the parameter that carried it, or by a parameter the
// endpoint declares.
func sits(path string, paths []string, param string, query url.Values, wantParam, queryKey string) bool {
	return matchesAny(path, paths) || param == wantParam || query.Has(queryKey)
}

// applyScheme reads the payload that worked. A scheme other than http or https
// reaching a sink is script execution, not navigation.
func applyScheme(caps model.CapabilitySet, payload string) model.CapabilitySet {
	lower := strings.ToLower(strings.TrimSpace(payload))

	switch {
	case strings.HasPrefix(lower, "javascript:"):
		caps.JavaScriptScheme = true
	case strings.HasPrefix(lower, "data:"):
		caps.DataScheme = true
	case strings.HasPrefix(lower, "http://"):
		// A destination the target accepts over plain http is a downgrade,
		// which is what makes a redirect useful for stripping TLS.
		caps.CrossProtocol = true
	}

	return caps
}

// applyTechnique adds what a technique's class implies on its own.
func applyTechnique(caps model.CapabilitySet, technique string) model.CapabilitySet {
	switch technique {
	case "OR-D05", "OR-F04":
		caps.RefererLeak = true
	case "OR-F02":
		caps.CSPBypass = true
	case "OR-F03":
		caps.SSRFChain = true
	case "OR-F05":
		caps.PhishingVector = true
	case "OR-F06":
		caps.CSRFReferer = true
	case "OR-F08", "OR-E03":
		caps.CrossProtocol = true
	case "OR-F10":
		caps.CachePoisoned = true
	case "OR-E01":
		caps.JavaScriptScheme = true
	case "OR-E02":
		caps.DataScheme = true
	case "OR-A10":
		caps.OAuthRedirectURI = true
	case "OR-D04":
		caps.SAMLRelayState = true
	}

	return caps
}

// cacheHeaders mark a response a shared cache may store. Combined with an
// input-controlled redirect, that is the web-cache-poisoned redirect shape.
//
// Detecting it is all detour does. Actually poisoning a shared cache would
// affect every other user of that cache, which is not a scanner's call to
// make.
var cacheHeaders = []string{
	"x-cache", "cf-cache-status", "age:", "x-varnish", "x-served-by",
	"cache-control: public", "s-maxage",
}

func applyEvidence(caps model.CapabilitySet, evidence []string) model.CapabilitySet {
	for _, line := range evidence {
		lower := strings.ToLower(line)

		if matchesAny(lower, cacheHeaders) {
			caps.CachePoisoned = true
		}

		if strings.Contains(lower, "referer") {
			caps.RefererLeak = true
		}
	}

	return caps
}

func matchesAny(haystack string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(haystack, needle) {
			return true
		}
	}

	return false
}

// Names lists the escalation capabilities a set carries, for reporting.
func Names(c model.CapabilitySet) []string {
	out := []string{}

	for _, entry := range []struct {
		on   bool
		name string
	}{
		{c.OAuthRedirectURI, "oauth.redirect_uri"},
		{c.PostLogoutRedirect, "oidc.post_logout_redirect_uri"},
		{c.SAMLRelayState, "saml.relaystate"},
		{c.JavaScriptScheme, "javascript_scheme"},
		{c.DataScheme, "data_scheme"},
		{c.CSPBypass, "csp_bypass"},
		{c.SSRFChain, "ssrf_chain"},
		{c.RefererLeak, "referer_leak"},
		{c.CSRFReferer, "csrf.referer_bypass"},
		{c.CachePoisoned, "cache_poisoned"},
		{c.CrossProtocol, "cross_protocol"},
		{c.PhishingVector, "phishing_vector"},
	} {
		if entry.on {
			out = append(out, entry.name)
		}
	}

	return out
}
