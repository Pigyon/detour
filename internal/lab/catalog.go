package lab

import (
	"encoding/json"
	"fmt"
	"io"
)

// Kind classifies a catalog entry.
type Kind string

const (
	// KindVuln is a true-positive technique fixture.
	KindVuln Kind = "vuln"
	// KindDecoy must stay at zero findings.
	KindDecoy Kind = "decoy"
	// KindSink is the loopback landing page used to prove a final hop.
	KindSink Kind = "sink"
	// KindScenario is a vendor or escalation setup that covers one or more ids.
	KindScenario Kind = "scenario"
)

const paramURL = "url"

// Endpoint describes one lab route for tests and detour lab --list.
type Endpoint struct {
	ID          string   `json:"id,omitempty"`
	Path        string   `json:"path"`
	Probe       string   `json:"probe"`
	Param       string   `json:"param,omitempty"`
	Kind        Kind     `json:"kind"`
	Covers      []string `json:"covers,omitempty"`
	Description string   `json:"description"`
}

// TechniqueIDs is the stable OR-* set from REFERENCE.md (43 ids).
var TechniqueIDs = []string{
	"OR-A01", "OR-A02", "OR-A03", "OR-A04", "OR-A05",
	"OR-A06", "OR-A07", "OR-A08", "OR-A09", "OR-A10",
	"OR-A11", "OR-A12", "OR-A13", "OR-A14", "OR-A15",
	"OR-B01", "OR-B02", "OR-B03", "OR-B04", "OR-B05",
	"OR-C01", "OR-C02", "OR-C03", "OR-C04",
	"OR-D01", "OR-D02", "OR-D03", "OR-D04", "OR-D05", "OR-D06",
	"OR-E01", "OR-E02", "OR-E03",
	"OR-F01", "OR-F02", "OR-F03", "OR-F04", "OR-F05",
	"OR-F06", "OR-F07", "OR-F08", "OR-F09", "OR-F10",
}

var catalog = []Endpoint{
	{ID: "OR-A01", Path: "/a01", Probe: "/a01", Param: paramURL, Kind: KindVuln, Description: "prefix allowlist; userinfo confusion"},
	{ID: "OR-A02", Path: "/a02", Probe: "/a02", Param: paramURL, Kind: KindVuln, Description: "plain @ rejected; delimiter stuffing allowed"},
	{ID: "OR-A03", Path: "/a03", Probe: "/a03", Param: paramURL, Kind: KindVuln, Description: "RFC 3986 relative check; backslash passes"},
	{ID: "OR-A04", Path: "/a04", Probe: "/a04", Param: paramURL, Kind: KindVuln, Description: "Spring-like userinfo terminator at ["},
	{ID: "OR-A05", Path: "/a05", Probe: "/a05", Param: paramURL, Kind: KindVuln, Description: "raw-string host compare; unicode dot/solidus"},
	{ID: "OR-A06", Path: "/a06", Probe: "/a06", Param: paramURL, Kind: KindVuln, Description: "no WHATWG whitespace strip"},
	{ID: "OR-A07", Path: "/a07", Probe: "/a07", Param: paramURL, Kind: KindVuln, Description: "blocks http(s):// only; slash multiplication"},
	{ID: "OR-A08", Path: "/a08", Probe: "/a08", Param: paramURL, Kind: KindVuln, Description: "contains(allowed) on the whole string"},
	{ID: "OR-A09", Path: "/a09", Probe: "/a09", Param: paramURL, Kind: KindVuln, Description: "prefix match on the host token"},
	{ID: "OR-A10", Path: "/a10", Probe: "/a10", Param: "redirect_uri", Kind: KindVuln, Description: "wildcard redirect_uri prefix; path traversal"},
	{ID: "OR-A11", Path: "/a11/{rest...}", Probe: "/a11/safe", Kind: KindVuln, Description: "path reflected into Location; CRLF splits a second header"},
	{ID: "OR-A12", Path: "/a12", Probe: "/a12", Param: paramURL, Kind: KindVuln, Description: "NUL truncation before allowlist"},
	{ID: "OR-A13", Path: "/a13", Probe: "/a13", Param: paramURL, Kind: KindVuln, Description: "endswith on the raw URL string"},
	{ID: "OR-A14", Path: "/a14", Probe: "/a14", Param: paramURL, Kind: KindVuln, Description: "literal http(s):// blocklist; malformed scheme"},
	{ID: "OR-A15", Path: "/a15", Probe: "/a15", Param: paramURL, Kind: KindVuln, Description: "string blocklist of loopback dotted-quads"},
	{ID: "OR-B01", Path: "/track/click2/{blob}", Probe: "/track/click2/invalid.html", Kind: KindVuln, Description: "EngageLab-style base64url(zlib(json)) click wrapper"},
	{Path: "/track/click3/{blob}", Probe: "/track/click3/invalid.html", Kind: KindVuln, Covers: []string{"OR-B01"}, Description: "click wrapper whose destination is bound to a real message id but not to a synthetic one"},
	{ID: "OR-B02", Path: "/ls/click", Probe: "/ls/click", Param: "upn", Kind: KindVuln, Description: "SendGrid-style unsigned ct wrapper"},
	{ID: "OR-B03", Path: "/b03", Probe: "/b03", Param: "token", Kind: KindVuln, Description: "JWT claim destination, signature ignored"},
	{ID: "OR-B04", Path: "/b04", Probe: "/b04", Param: "next", Kind: KindVuln, Description: "validator decodes once; sink decodes twice"},
	{ID: "OR-B05", Path: "/b05", Probe: "/b05", Param: paramURL, Kind: KindVuln, Description: "first hop allowlists same-host inner redirector"},
	{Path: "/b05/inner", Probe: "/b05/inner", Param: paramURL, Kind: KindVuln, Description: "inner trusted redirector, open destination"},
	{ID: "OR-C01", Path: "/c01", Probe: "/c01", Param: "backUrl", Kind: KindVuln, Description: "SPA backUrl JS sink, 200 no Location"},
	{ID: "OR-C02", Path: "/c02", Probe: "/c02", Kind: KindVuln, Description: "location.hash sink, fragment never sent to the server"},
	{ID: "OR-C03", Path: "/c03", Probe: "/c03", Param: "src", Kind: KindVuln, Description: "unsandboxed iframe that can drive top.location"},
	{Path: "/c03/frame", Probe: "/c03/frame", Param: "to", Kind: KindVuln, Description: "iframe document assigning top.location"},
	{ID: "OR-C04", Path: "/c04", Probe: "/c04", Param: paramURL, Kind: KindVuln, Description: "meta refresh, 200 no Location"},
	{ID: "OR-D01", Path: "/d01", Probe: "/d01", Kind: KindVuln, Description: "X-Forwarded-Host reflected into Location"},
	{ID: "OR-D02", Path: "/_next/d02", Probe: "/_next/d02", Param: "destHost", Kind: KindVuln, Description: "Next.js-style hostname built from request input"},
	{ID: "OR-D03", Path: "/d03/{path...}", Probe: "/d03/", Kind: KindVuln, Description: "Location built from the raw path, not path.Clean"},
	{ID: "OR-D04", Path: "/saml/acs", Probe: "/saml/acs", Param: "RelayState", Kind: KindVuln, Description: "SAML RelayState free-text redirect"},
	{Path: "/oidc/logout", Probe: "/oidc/logout", Param: "post_logout_redirect_uri", Kind: KindVuln, Description: "OIDC post_logout_redirect_uri unvalidated"},
	{ID: "OR-D05", Path: "/d05", Probe: "/d05", Kind: KindVuln, Description: "Referer header used as the destination"},
	{ID: "OR-D06", Path: "/d06", Probe: "/d06", Param: paramURL, Kind: KindVuln, Description: "Refresh response header, 200 no Location"},
	{ID: "OR-E01", Path: "/e01", Probe: "/e01", Param: paramURL, Kind: KindVuln, Description: "JS sink with no javascript: scheme check"},
	{ID: "OR-E02", Path: "/e02", Probe: "/e02", Param: paramURL, Kind: KindVuln, Description: "JS sink that accepts data: URIs"},
	{ID: "OR-E03", Path: "/e03", Probe: "/e03", Param: paramURL, Kind: KindVuln, Description: "exact host allowlist that still permits http:"},
	{ID: "OR-F01", Path: "/oauth/authorize", Probe: "/oauth/authorize", Param: "redirect_uri", Kind: KindScenario, Description: "registered redirect_uri prefix check hiding a nested redirect"},
	{ID: "OR-F02", Path: "/csp/redir", Probe: "/csp/redir", Param: paramURL, Kind: KindScenario, Description: "open redirect on a CSP-allowlisted host"},
	{Path: "/csp", Probe: "/csp", Kind: KindScenario, Description: "page whose CSP allowlists allowed.lab"},
	{ID: "OR-F03", Path: "/ssrf/fetch", Probe: "/ssrf/fetch", Param: paramURL, Kind: KindScenario, Covers: []string{"OR-F07"}, Description: "server-side fetcher that follows in-lab hops only"},
	{ID: "OR-F04", Path: "/f04/reset", Probe: "/f04/reset", Param: "next", Kind: KindScenario, Description: "token in the URL plus off-site next"},
	{ID: "OR-F05", Path: "/f05", Probe: "/f05", Param: paramURL, Kind: KindScenario, Description: "open redirect suitable for first-party phishing"},
	{Path: "/login-page", Probe: "/login-page", Kind: KindScenario, Description: "sign-in lookalike used with OR-F05"},
	{ID: "OR-F06", Path: "/f06", Probe: "/f06", Param: paramURL, Kind: KindVuln, Description: "same-host-only redirector (CSRF Referer laundering primitive)"},
	{ID: "OR-F07", Path: "/f07/r1", Probe: "/f07/r1", Kind: KindVuln, Description: "multi-hop chain r1 to r2 to /landed, all on the lab"},
	{Path: "/f07/r2", Probe: "/f07/r2", Kind: KindVuln, Description: "second hop of the OR-F07 chain"},
	{ID: "OR-F08", Path: "/f08", Probe: "/f08", Param: paramURL, Kind: KindVuln, Description: "Location may change scheme; lab never fetches it"},
	{ID: "OR-F09", Path: "/f09", Probe: "/f09", Kind: KindVuln, Description: "target=_blank without rel=noopener"},
	{ID: "OR-F10", Path: "/f10", Probe: "/f10", Kind: KindVuln, Description: "cacheable X-Forwarded-Host poisoning on a throwaway cb key"},
	{Path: "/landed", Probe: "/landed", Kind: KindSink, Description: "loopback canary sink; proves the final hop without leaving the box"},
	{Path: "/auth/back", Probe: "/auth/back", Param: "backUrl", Kind: KindVuln, Description: "post-login backUrl; 200 with no sink until lab_session is set"},
	{Path: "/login", Probe: "/login", Kind: KindScenario, Description: "sets lab_session=authed"},
	{Path: "/app/signin", Probe: "/app/signin", Kind: KindVuln, Covers: []string{"OR-C01", "OR-A13", "OR-E01"}, Description: "signin bundle whose guard matches the allowlist as a suffix"},
	{Path: "/static/app.js", Probe: "/static/app.js", Kind: KindVuln, Description: "loose guard bundle served to /app/signin"},
	{Path: "/decoy/guarded", Probe: "/decoy/guarded", Kind: KindDecoy, Description: "bundle with a correct guard; exact host equality, https only"},
	{Path: "/static/safe.js", Probe: "/static/safe.js", Kind: KindDecoy, Description: "correct guard bundle served to /decoy/guarded"},
	{Path: "/decoy/allowlist", Probe: "/decoy/allowlist", Param: "backUrl", Kind: KindDecoy, Description: "exact hostname equality, userinfo and javascript blocked"},
	{Path: "/decoy/static", Probe: "/decoy/static", Kind: KindDecoy, Description: "static redirect to https://allowed.lab/home"},
	{Path: "/decoy/reflect", Probe: "/decoy/reflect", Param: paramURL, Kind: KindDecoy, Description: "reflection only, no navigation"},
	{Path: "/decoy/downgrade", Probe: "/decoy/downgrade", Param: paramURL, Kind: KindDecoy, Description: "http downgrade to allowed.lab only; info, not a finding"},
	{Path: "/decoy/signed/{blob}", Probe: "/decoy/signed/invalid", Kind: KindDecoy, Description: "HMAC-verified destination blob"},
}

// Catalog returns a copy of the lab endpoint list.
func Catalog() []Endpoint {
	out := make([]Endpoint, len(catalog))
	copy(out, catalog)

	for i := range out {
		if catalog[i].Covers != nil {
			out[i].Covers = append([]string{}, catalog[i].Covers...)
		}
	}

	return out
}

// WriteCatalog prints the endpoint list as indented JSON.
func WriteCatalog(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	if err := enc.Encode(Catalog()); err != nil {
		return fmt.Errorf("encoding catalog: %w", err)
	}

	return nil
}
