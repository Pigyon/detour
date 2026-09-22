package report

// technique is what a report says about one technique id: what it is, and
// what to change.
//
// One table rather than two. A title and its fix belong to the same technique,
// and keeping them together is what stops a report naming a defect it has no
// advice for.
type technique struct {
	Title string
	Fix   string
}

// techniques covers every id in REFERENCE.md.
var techniques = map[string]technique{
	"OR-A01": {
		Title: "Prefix allowlist defeated by userinfo confusion",
		Fix:   "Parse the URL and compare the parsed hostname for exact equality; reject any URL carrying userinfo.",
	},
	"OR-A02": {
		Title: "Delimiter stuffing past an @ blocklist",
		Fix:   "Compare the parsed hostname, not the raw string, and reject userinfo outright.",
	},
	"OR-A03": {
		Title: "Backslash treated as a path separator by the browser only",
		Fix:   "Normalize backslashes to forward slashes before validating, or reject them.",
	},
	"OR-A04": {
		Title: "Userinfo terminator differs between parser and framework",
		Fix:   "Use one URL parser for validation and navigation, and reject userinfo.",
	},
	"OR-A05": {
		Title: "Raw-string host comparison defeated by unicode lookalikes",
		Fix:   "Compare IDNA-canonicalized hostnames rather than raw strings.",
	},
	"OR-A06": {
		Title: "Whitespace and control characters stripped by the browser only",
		Fix:   "Strip tab, CR, and LF before validating, the way a browser does.",
	},
	"OR-A07": {
		Title: "Scheme blocklist defeated by slash multiplication",
		Fix:   "Validate the parsed URL rather than blocklisting scheme prefixes.",
	},
	"OR-A08": {
		Title: "Substring containment check on the whole URL",
		Fix:   "Compare the parsed hostname for equality instead of testing containment.",
	},
	"OR-A09": {
		Title: "Unanchored prefix match on the host",
		Fix:   "Anchor the host match at both ends, or compare for equality.",
	},
	"OR-A10": {
		Title: "Wildcard redirect_uri prefix allows path traversal",
		Fix:   "Match registered redirect URIs exactly, including the path.",
	},
	"OR-A11": {
		Title: "CRLF injection splits a second Location header",
		Fix:   "Reject CR and LF in any value reflected into a response header.",
	},
	"OR-A12": {
		Title: "NUL truncation before the allowlist check",
		Fix:   "Reject NUL bytes before validation rather than truncating.",
	},
	"OR-A13": {
		Title: "Unanchored suffix match on the host",
		Fix:   "Anchor the host match at both ends, or compare for equality.",
	},
	"OR-A14": {
		Title: "Malformed scheme autocorrected by the browser",
		Fix:   "Validate the parsed scheme against an allowlist of http and https.",
	},
	"OR-A15": {
		Title: "String blocklist of loopback addresses",
		Fix:   "Resolve the host and check the address, rather than blocklisting strings.",
	},
	"OR-B01": {
		Title: "Destination buried in a compressed opaque blob",
		Fix:   "Sign the envelope and verify the signature, covering the destination field.",
	},
	"OR-B02": {
		Title: "Unsigned vendor click wrapper",
		Fix:   "Authenticate the wrapper so a destination cannot be forged.",
	},
	"OR-B03": {
		Title: "Destination in an unverified JWT claim",
		Fix:   "Verify the token signature before reading any claim.",
	},
	"OR-B04": {
		Title: "Validator decodes once where the sink decodes twice",
		Fix:   "Decode exactly once, then validate the decoded value.",
	},
	"OR-B05": {
		Title: "Chained trusted redirector completes the hop",
		Fix:   "Validate the final destination, not just the first hop's host.",
	},
	"OR-C01": {
		Title: "Client-side route guard navigates without server evidence",
		Fix:   "Apply the same destination allowlist client side that the server would apply.",
	},
	"OR-C02": {
		Title: "DOM sink fed from location.hash, invisible to the server",
		Fix:   "Validate location.hash against an allowlist before assigning it to a sink.",
	},
	"OR-C03": {
		Title: "Unsandboxed frame can drive top-level navigation",
		Fix:   "Add a sandbox attribute to frames rendering untrusted content.",
	},
	"OR-C04": {
		Title: "Meta refresh navigates on a 200 response",
		Fix:   "Validate the destination before rendering it into a meta refresh.",
	},
	"OR-D01": {
		Title: "Location built from a request header",
		Fix:   "Build absolute URLs from configuration, never from a request header.",
	},
	"OR-D02": {
		Title: "Hostname built from request input",
		Fix:   "Build the hostname from configuration, never from request input.",
	},
	"OR-D03": {
		Title: "Location built from the raw path",
		Fix:   "Clean and validate the path before reflecting it into a Location.",
	},
	"OR-D04": {
		Title: "SAML RelayState accepted as free text",
		Fix:   "Validate RelayState against an allowlist of relative paths.",
	},
	"OR-D05": {
		Title: "Referer header used as the destination",
		Fix:   "Never use the Referer header as a navigation destination.",
	},
	"OR-D06": {
		Title: "Refresh response header navigates on a 200",
		Fix:   "Validate the destination before emitting a Refresh header.",
	},
	"OR-E01": {
		Title: "javascript: scheme reaches a navigation sink",
		Fix:   "Restrict the scheme to http and https before assigning to a sink.",
	},
	"OR-E02": {
		Title: "data: URI reaches a navigation sink",
		Fix:   "Restrict the scheme to http and https before assigning to a sink.",
	},
	"OR-E03": {
		Title: "Allowlist permits http, enabling a TLS downgrade",
		Fix:   "Require https on the allowlist so a downgrade is impossible.",
	},
	"OR-F01": {
		Title: "OAuth redirect_uri bypass, enabling token theft",
		Fix:   "Match registered redirect URIs exactly and bind them to the client id.",
	},
	"OR-F02": {
		Title: "Open redirect on a CSP-allowlisted host",
		Fix:   "Remove the redirect from the CSP-allowlisted host, or drop it from the allowlist.",
	},
	"OR-F03": {
		Title: "Server-side fetcher follows cross-host redirects",
		Fix:   "Do not follow cross-host redirects in server-side fetchers.",
	},
	"OR-F04": {
		Title: "Password reset token leaked through a redirect",
		Fix:   "Keep single-use tokens out of URLs that can redirect off-site.",
	},
	"OR-F05": {
		Title: "First-party phishing vector on a trusted domain",
		Fix:   "Validate the destination so the domain cannot host attacker content.",
	},
	"OR-F06": {
		Title: "Same-host redirector launders the Referer for CSRF",
		Fix:   "Validate the destination so the host cannot launder a Referer.",
	},
	"OR-F07": {
		Title: "Multi-hop redirect chain",
		Fix:   "Validate the final destination of the chain, not each hop in isolation.",
	},
	"OR-F08": {
		Title: "Cross-protocol redirect",
		Fix:   "Require https on the destination.",
	},
	"OR-F09": {
		Title: "Reverse tabnabbing through a missing rel=noopener",
		Fix:   "Add rel=noopener noreferrer to every external target=_blank link.",
	},
	"OR-F10": {
		Title: "Web cache poisoned with a redirect",
		Fix:   "Exclude request-header-derived values from the cache key, or stop reflecting them.",
	},
}

const (
	defaultTitle       = "Open redirect"
	defaultRemediation = "Validate the destination against an exact-match allowlist of hosts you control."
)

// techniqueTitle names a technique in one line.
func techniqueTitle(id string) string {
	if t, ok := techniques[id]; ok && t.Title != "" {
		return t.Title
	}

	return defaultTitle
}

// Remediation is the one-line fix for a technique, so a report tells a
// developer what to change rather than only what is broken.
func Remediation(id string) string {
	if t, ok := techniques[id]; ok && t.Fix != "" {
		return t.Fix
	}

	return defaultRemediation
}
