package corpus

import (
	"net/url"
	"strings"
)

// Vendor is one email or marketing platform whose click wrapper is a known
// product rather than a one-off.
//
// This is why the class is worth a named check: the format is reusable across
// every program using that vendor, and the wrapper is designed to redirect
// anywhere the campaign says, on a domain the customer owns.
type Vendor struct {
	Name string
	// HostSuffix matches the vendor's own tracking domain, when it has one.
	HostSuffix string
	// PathPrefix matches the wrapper path, which survives being served from a
	// customer-branded subdomain.
	PathPrefix string
	// Param is a parameter the wrapper always carries.
	Param string
}

// vendors are the formats documented by the vendors themselves and widely
// abused in the wild.
var vendors = []Vendor{
	{Name: "engagelab", PathPrefix: "/track/click2/"},
	{Name: "engagelab", HostSuffix: "engagelab.email"},
	{Name: "sendgrid", HostSuffix: "ct.sendgrid.net", Param: "upn"},
	{Name: "sendgrid", PathPrefix: "/ls/click", Param: "upn"},
	{Name: "braze", PathPrefix: "/api/v3/click"},
	{Name: "braze", HostSuffix: "braze.com"},
	{Name: "iterable", PathPrefix: "/a/click"},
	{Name: "iterable", HostSuffix: "iterable.com"},
	{Name: "salesforce-mc", Param: "qs"},
	{Name: "adobe-campaign", PathPrefix: "/r/", Param: "id"},
	{Name: "mailgun", HostSuffix: "mailgun.org"},
	{Name: "mailchimp", HostSuffix: "list-manage.com"},
	{Name: "hubspot", HostSuffix: "hubspotlinks.com"},
	{Name: "marketo", HostSuffix: "mktoresp.com"},
	{Name: "klaviyo", HostSuffix: "kmail-lists.com"},
	{Name: "sparkpost", HostSuffix: "spmailtechno.com"},
}

// MatchVendor recognizes a click-wrapper format. A path or parameter match
// counts on any host, because the wrapper is routinely served from the
// customer's own subdomain, which is exactly what makes it valuable.
func MatchVendor(raw string) (string, bool) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", false
	}

	host := strings.ToLower(parsed.Hostname())
	path := strings.ToLower(parsed.EscapedPath())
	query := parsed.Query()

	for _, v := range vendors {
		if v.HostSuffix != "" && hostMatches(host, v.HostSuffix) {
			return v.Name, true
		}

		if v.PathPrefix != "" && strings.HasPrefix(path, v.PathPrefix) {
			if v.Param == "" || query.Has(v.Param) {
				return v.Name, true
			}
		}
	}

	return "", false
}

func hostMatches(host, suffix string) bool {
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}

// cnameVendors are the platforms a customer subdomain is commonly delegated
// to. A CNAME pointing at one means first-party trust on third-party code.
var cnameVendors = map[string]string{
	"sendgrid.net":       "sendgrid",
	"engagelab.email":    "engagelab",
	"braze.com":          "braze",
	"iterable.com":       "iterable",
	"exacttarget.com":    "salesforce-mc",
	"mktoresp.com":       "marketo",
	"hubspotlinks.com":   "hubspot",
	"list-manage.com":    "mailchimp",
	"mailgun.org":        "mailgun",
	"kmail-lists.com":    "klaviyo",
	"spmailtechno.com":   "sparkpost",
	"cust-spf.com":       "esp-generic",
	"customeriomail.com": "customer-io",
	"sparkpostmail.com":  "sparkpost",
	"mcsv.net":           "mailchimp",
	"rs6.net":            "constant-contact",
}

// MatchCNAME names the platform a hostname is delegated to, if any. A
// customer subdomain pointing at an ESP is a priority target: the wrapper
// runs on the customer's domain, with the customer's certificate, and every
// allowlist trusts it.
func MatchCNAME(cname string) (string, bool) {
	host := strings.Trim(strings.ToLower(strings.TrimSpace(cname)), ".")
	if host == "" {
		return "", false
	}

	for suffix, name := range cnameVendors {
		if hostMatches(host, suffix) {
			return name, true
		}
	}

	return "", false
}
