// Package resolve interprets redirect destinations the way servers and browsers do.
package resolve

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
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

	return RFC3986(base, autocorrectScheme(folded))
}

// schemeOnly matches a special scheme followed by something that is a host
// rather than an opaque payload: "https:example.com/path".
var schemeOnly = regexp.MustCompile(`^(?i)(https?):([a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+)(?:[:/?#]|$)`)

// autocorrectScheme supplies the slashes a browser infers after a special
// scheme.
//
// "https:example.com" has no authority under RFC 3986, so net/url reads
// example.com as an opaque payload and reports no host at all. Browsers treat
// the special schemes differently and navigate to the host, which is the whole
// point of the malformed-scheme payloads: a blocklist searching for "https://"
// never fires, and the navigation happens anyway.
func autocorrectScheme(loc string) string {
	match := schemeOnly.FindStringSubmatch(loc)
	if match == nil {
		return loc
	}

	scheme := match[1]

	return scheme + "://" + loc[len(scheme)+1:]
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

// mapIPv4Literal canonicalizes every spelling of an IPv4 (or IPv4-mapped
// IPv6) address to one dotted quad.
//
// A validator that blocklists the string "127.0.0.1" never sees 2130706433,
// 0x7f000001 or 0177.0.0.1, yet every one of them reaches the same address,
// because the resolver follows inet_aton rather than the dotted-quad grammar.
// Canonicalizing here is what lets the equality check upstream be honest.
func mapIPv4Literal(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}

		return ip.String()
	}

	if n, ok := inetAton(host); ok {
		return intToIPv4(n)
	}

	return ""
}

// maxIPv4Parts is the dotted-part ceiling inet_aton accepts.
const maxIPv4Parts = 4

// inetAton parses the historical a, a.b, a.b.c and a.b.c.d forms, each part in
// decimal, octal or hex, the way the C library and every network stack still
// do.
func inetAton(host string) (uint32, bool) {
	if host == "" || strings.HasSuffix(host, ".") {
		return 0, false
	}

	parts := strings.Split(host, ".")
	if len(parts) > maxIPv4Parts {
		return 0, false
	}

	values := make([]uint64, 0, len(parts))

	for _, part := range parts {
		n, ok := parseIPv4Part(part)
		if !ok {
			return 0, false
		}

		values = append(values, n)
	}

	// The final part absorbs every byte the leading parts did not name, which
	// is what makes 127.1 and 0x7f.1 the addresses they are.
	last := values[len(values)-1]
	lead := values[:len(values)-1]

	shift := (maxIPv4Parts - len(lead)) * 8
	if last >= 1<<shift {
		return 0, false
	}

	var out uint64

	for i, v := range lead {
		if v > 0xff {
			return 0, false
		}

		out |= v << ((maxIPv4Parts - 1 - i) * 8)
	}

	combined := out | last
	if combined > math.MaxUint32 {
		return 0, false
	}

	return uint32(combined), true
}

// parseIPv4Part reads one component under inet_aton's radix rules: 0x is hex,
// a leading zero is octal, anything else decimal.
func parseIPv4Part(part string) (uint64, bool) {
	if part == "" {
		return 0, false
	}

	base, digits := 10, part

	switch {
	case len(part) > 2 && (strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X")):
		base, digits = 16, part[2:]
	case len(part) > 1 && part[0] == '0':
		base, digits = 8, part[1:]
	}

	n, err := strconv.ParseUint(digits, base, 64)
	if err != nil || n > math.MaxUint32 {
		return 0, false
	}

	return n, true
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

// HitsCanary reports whether either interpretation's host is the canary, or
// anything under it.
//
// A subdomain counts. Several techniques land on allowed.example.canary rather
// than on the canary itself: a prefix-matching validator is beaten by appending
// the attacker's domain, and a unicode dot normalizes into a real one. Whoever
// holds the canary holds every name beneath it, so equality alone would report
// those endpoints clean.
func HitsCanary(pair Pair, canary string) bool {
	if CanonicalHost(canary) == "" {
		return false
	}

	return HostSuffix(pair.RFC.Host, canary) || HostSuffix(pair.Browser.Host, canary)
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
	canaryHitRFC := pair.RFC.Host != "" && HostSuffix(pair.RFC.Host, canary)
	canaryHitBrowser := pair.Browser.Host != "" && HostSuffix(pair.Browser.Host, canary)

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

// ParseRefresh extracts the destination from a Refresh directive, in either
// the header or a meta tag.
//
// The "url=" prefix is optional. The HTML standard skips it if present and
// takes the rest of the value as the URL either way, so "0;https://host/"
// navigates exactly like "0;url=https://host/". Requiring the prefix missed
// the shorter form, which real applications emit.
func ParseRefresh(header string) (string, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", false
	}

	// The offset has to be taken on the string it indexes. strings.ToLower can
	// change a string's byte length, so an index found in a lowercased copy
	// does not point at the same place in the original.
	var rest string

	if idx := indexFold(header, "url="); idx >= 0 {
		rest = header[idx+len("url="):]
	} else if _, after, found := strings.Cut(header, ";"); found {
		rest = after
	} else if _, after, found := strings.Cut(header, ","); found {
		rest = after
	} else {
		return "", false
	}

	rest = trimMatchingQuotes(strings.TrimSpace(rest))
	if rest == "" {
		return "", false
	}

	return rest, true
}

// trimMatchingQuotes removes a quote pair around a value.
//
// Trimming both quote characters from both ends instead eats a quote that is
// part of the value: content="0;url=/x?a='b'" ends in a quote the URL owns.
func trimMatchingQuotes(s string) string {
	if len(s) < 2 {
		return s
	}

	first, last := s[0], s[len(s)-1]
	if (first == '"' || first == '\'') && first == last {
		return s[1 : len(s)-1]
	}

	return s
}

// indexFold is strings.Index without regard to case, returning an offset into
// s itself.
func indexFold(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if strings.EqualFold(s[i:i+len(substr)], substr) {
			return i
		}
	}

	return -1
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
	`(?is)<meta[\s/][^>]*?http-equiv\s*=\s*(?:"refresh"|'refresh'|refresh(?:[\s/>]|$))[^>]*?content\s*=\s*(?:"([^"]+)"|'([^']+)'|([^"'>\s]+))`)

// metaRefreshReversed handles the attribute order the other way round.
var metaRefreshReversed = regexp.MustCompile(
	`(?is)<meta[\s/][^>]*?content\s*=\s*(?:"([^"]+)"|'([^']+)'|([^"'>\s]+))[^>]*?http-equiv\s*=\s*(?:"refresh"|'refresh'|refresh(?:[\s/>]|$))`)

// MetaRefresh extracts every destination a meta refresh tag in body names.
//
// All of them, because a page may carry a benign refresh ahead of the
// attacker-controlled one and returning only the first hides the finding.
//
// Regions that look like markup but are not are stripped first: a refresh tag
// quoted inside a comment, a script, or a textarea navigates nothing, and
// reporting one is a false positive against a page detour did not understand.
func MetaRefresh(body []byte) ([]string, bool) {
	cleaned := stripInertMarkup(body)
	out := []string{}
	seen := map[string]struct{}{}

	for _, re := range []*regexp.Regexp{metaRefresh, metaRefreshReversed} {
		for _, match := range re.FindAllSubmatch(cleaned, -1) {
			for _, group := range match[1:] {
				if len(group) == 0 {
					continue
				}

				dest, ok := ParseRefresh(string(group))
				if !ok {
					continue
				}

				if _, dup := seen[dest]; dup {
					continue
				}

				seen[dest] = struct{}{}

				out = append(out, dest)
			}
		}
	}

	return out, len(out) > 0
}

// inertRegions are the places markup is text rather than markup.
//
// Raw-text elements come first, and comments last. A "<!--" inside a script
// string is not a comment, but stripping comments first pairs it with a later
// "-->" and deletes everything between, including a real refresh tag.
//
// Each alternative ends at its closing tag or at end of input. An unterminated
// region runs to the end of what was read, which is what a browser does, and
// is what the response body being truncated at a read limit looks like.
var inertRegions = []*regexp.Regexp{
	regexp.MustCompile(`(?is)<script\b.*?(?:</script\s*>|$)`),
	regexp.MustCompile(`(?is)<style\b.*?(?:</style\s*>|$)`),
	regexp.MustCompile(`(?is)<textarea\b.*?(?:</textarea\s*>|$)`),
	regexp.MustCompile(`(?is)<template\b.*?(?:</template\s*>|$)`),
	regexp.MustCompile(`(?is)<!--.*?(?:-->|$)`),
}

// stripInertMarkup blanks the regions a browser never parses as tags.
func stripInertMarkup(body []byte) []byte {
	out := body
	for _, re := range inertRegions {
		out = re.ReplaceAll(out, nil)
	}

	return out
}
