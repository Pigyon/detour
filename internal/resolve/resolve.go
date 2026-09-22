// Package resolve interprets redirect destinations the way servers and browsers do.
package resolve

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

// Kind names one URL interpretation.
type Kind string

const (
	// KindRFC3986 is Go net/url / RFC 3986 resolution.
	KindRFC3986 Kind = "rfc3986"
	// KindBrowser is a WHATWG-ish view: backslash as slash, tab/CR/LF stripped.
	KindBrowser Kind = "browser"
)

// Interpretation is one resolved view of a Location (or Refresh) value.
type Interpretation struct {
	Kind     Kind
	Raw      string
	Resolved string
	Host     string
}

// Pair is the RFC and browser readings of the same destination.
type Pair struct {
	RFC     Interpretation
	Browser Interpretation
}

// Interpret resolves loc against base under both parsers.
func Interpret(base, loc string) (Pair, error) {
	rfcURL, err := RFC3986(base, loc)
	if err != nil {
		return Pair{}, err
	}

	browserURL, err := Browser(base, loc)
	if err != nil {
		return Pair{}, err
	}

	return Pair{
		RFC:     asInterpretation(KindRFC3986, loc, rfcURL),
		Browser: asInterpretation(KindBrowser, loc, browserURL),
	}, nil
}

func asInterpretation(kind Kind, raw string, u *url.URL) Interpretation {
	host := ""
	resolved := ""

	if u != nil {
		resolved = u.String()
		host = CanonicalHost(u.Hostname())
	}

	return Interpretation{Kind: kind, Raw: raw, Resolved: resolved, Host: host}
}

// RFC3986 resolves loc against base using net/url.
func RFC3986(base, loc string) (*url.URL, error) {
	ref, err := url.Parse(loc)
	if err != nil {
		return nil, fmt.Errorf("rfc3986 parse: %w", err)
	}

	if base == "" {
		return ref, nil
	}

	baseURL, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("rfc3986 base: %w", err)
	}

	return baseURL.ResolveReference(ref), nil
}

// Browser folds WHATWG slash and whitespace quirks, then resolves.
func Browser(base, loc string) (*url.URL, error) {
	folded := whatwgPrep(loc)

	return RFC3986(base, folded)
}

func whatwgPrep(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	for _, r := range s {
		switch r {
		case '\\':
			b.WriteByte('/')
		case '\t', '\n', '\r':
			continue
		default:
			b.WriteRune(r)
		}
	}

	out := strings.TrimFunc(b.String(), func(r rune) bool {
		return r <= 0x20 || unicode.IsControl(r)
	})

	return collapseLeadingSlashes(out)
}

func collapseLeadingSlashes(s string) string {
	if !strings.HasPrefix(s, "//") {
		return s
	}

	i := 0
	for i < len(s) && s[i] == '/' {
		i++
	}

	return "//" + s[i:]
}

// CanonicalHost lowercases, applies IDNA, and maps alternate IPv4 encodings.
func CanonicalHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	host = strings.ToLower(host)

	if host == "" {
		return ""
	}

	if mapped := mapIPv4Literal(host); mapped != "" {
		return mapped
	}

	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || ascii == "" {
		return host
	}

	return ascii
}

func mapIPv4Literal(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}

		return ip.String()
	}

	if strings.HasPrefix(host, "0x") {
		n, err := strconv.ParseUint(host[2:], 16, 32)
		if err == nil {
			return intToIPv4(uint32(n))
		}
	}

	if n, err := strconv.ParseUint(host, 10, 32); err == nil && host != "0" {
		if !strings.Contains(host, ".") {
			return intToIPv4(uint32(n))
		}
	}

	return ""
}

func intToIPv4(n uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)

	return net.IP(b[:]).String()
}

// SameHost is true when a and b are the same host after canonicalization.
func SameHost(a, b string) bool {
	ca, cb := CanonicalHost(a), CanonicalHost(b)

	return ca != "" && ca == cb
}

// HostSuffix is true when host equals suffix or is a subdomain of it.
func HostSuffix(host, suffix string) bool {
	h, s := CanonicalHost(host), CanonicalHost(suffix)
	if h == "" || s == "" {
		return false
	}

	return h == s || strings.HasSuffix(h, "."+s)
}

// HitsCanary reports whether either interpretation's host is the canary.
func HitsCanary(pair Pair, canary string) bool {
	canary = CanonicalHost(canary)
	if canary == "" {
		return false
	}

	return pair.RFC.Host == canary || pair.Browser.Host == canary
}

// OffOrigin reports whether either interpretation leaves base's host.
func OffOrigin(base string, pair Pair) bool {
	u, err := url.Parse(base)
	if err != nil {
		return false
	}

	origin := CanonicalHost(u.Hostname())
	if origin == "" {
		return false
	}

	if pair.RFC.Host != "" && pair.RFC.Host != origin {
		return true
	}

	return pair.Browser.Host != "" && pair.Browser.Host != origin
}

// NeedsBrowserConfirm is true when only the browser view leaves origin / hits canary.
func NeedsBrowserConfirm(base, canary string, pair Pair) bool {
	canaryHitRFC := pair.RFC.Host != "" && SameHost(pair.RFC.Host, canary)
	canaryHitBrowser := pair.Browser.Host != "" && SameHost(pair.Browser.Host, canary)

	if canaryHitBrowser && !canaryHitRFC {
		return true
	}

	u, err := url.Parse(base)
	if err != nil {
		return false
	}

	origin := CanonicalHost(u.Hostname())
	rfcOff := pair.RFC.Host != "" && pair.RFC.Host != origin
	browserOff := pair.Browser.Host != "" && pair.Browser.Host != origin

	return browserOff && !rfcOff
}

// ParseRefresh extracts the url= value from a Refresh response header.
func ParseRefresh(header string) (string, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", false
	}

	lower := strings.ToLower(header)

	idx := strings.Index(lower, "url=")
	if idx < 0 {
		return "", false
	}

	rest := strings.TrimSpace(header[idx+4:])
	rest = strings.Trim(rest, `"'`)

	if rest == "" {
		return "", false
	}

	return rest, true
}

// LocationsFromRaw returns every Location header value from a raw HTTP head.
func LocationsFromRaw(raw []byte) []string {
	head := headerBlock(raw)
	found := []string{}

	for _, line := range splitHeaderLines(head) {
		if len(line) == 0 {
			continue
		}

		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}

		if !strings.EqualFold(string(name), "Location") {
			continue
		}

		found = append(found, string(bytes.TrimSpace(value)))
	}

	return found
}

func headerBlock(raw []byte) []byte {
	if head, _, ok := bytes.Cut(raw, []byte("\r\n\r\n")); ok {
		return head
	}

	if head, _, ok := bytes.Cut(raw, []byte("\n\n")); ok {
		return head
	}

	return raw
}

func splitHeaderLines(head []byte) [][]byte {
	if bytes.Contains(head, []byte("\r\n")) {
		return bytes.Split(head, []byte("\r\n"))
	}

	return bytes.Split(head, []byte("\n"))
}

// metaRefresh matches a meta refresh directive in a response body. The browser
// navigates on it while the status stays 200, so a header-only scanner records
// a miss.
var metaRefresh = regexp.MustCompile(
	`(?is)<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']([^"']+)["']`)

// metaRefreshReversed handles the attribute order the other way round.
var metaRefreshReversed = regexp.MustCompile(
	`(?is)<meta[^>]+content\s*=\s*["']([^"']+)["'][^>]*http-equiv\s*=\s*["']?refresh["']?`)

// MetaRefresh extracts the destination from a meta refresh tag in body.
func MetaRefresh(body []byte) (string, bool) {
	for _, re := range []*regexp.Regexp{metaRefresh, metaRefreshReversed} {
		match := re.FindSubmatch(body)
		if match == nil {
			continue
		}

		if dest, ok := ParseRefresh(string(match[1])); ok {
			return dest, true
		}
	}

	return "", false
}
