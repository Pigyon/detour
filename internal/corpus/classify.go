package corpus

import (
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/nedlir/detour/internal/decode"
)

// Kind says why a URL is worth attacking. A URL can earn several.
type Kind string

const (
	// KindParamName is a parameter whose name is redirect shaped.
	KindParamName Kind = "param-name"
	// KindParamValue is a parameter whose value already looks like a URL,
	// which is the strongest signal of all: the app puts destinations here.
	KindParamValue Kind = "param-value"
	// KindPath is a high-entropy path segment that may be encoded state.
	KindPath Kind = "path"
	// KindVendorSig is a known ESP or martech click-wrapper format.
	KindVendorSig Kind = "vendor-sig"
)

// redirectParams are the parameter names that carry a destination. Shared
// with the attack engine's own list by intent, kept here so classification
// does not depend on the engine.
var redirectParams = map[string]struct{}{
	"url": {}, "next": {}, "redirect": {}, "redirect_uri": {}, "redirecturl": {},
	"return": {}, "returnurl": {}, "return_to": {}, "returnto": {},
	"back": {}, "backurl": {}, "back_url": {}, "dest": {}, "destination": {},
	"goto": {}, "continue": {}, "rurl": {}, "redir": {}, "r": {}, "u": {},
	"uri": {}, "target": {}, "to": {}, "out": {}, "forward": {}, "link": {},
	"callback": {}, "relaystate": {}, "checkout_url": {}, "image_url": {},
	"go": {}, "login_url": {}, "logout_url": {}, "post_logout_redirect_uri": {},
	"service": {}, "ref": {}, "referrer": {}, "domain": {}, "host": {},
	"desthost": {}, "dest_host": {}, "hostname": {},
}

// RedirectParams returns the canonical redirect-shaped parameter names,
// sorted.
//
// This is the single list. The classifier decides what is worth attacking and
// the attack engine decides what to probe, and when those two disagree the
// engine silently skips endpoints selection just flagged.
func RedirectParams() []string {
	out := make([]string, 0, len(redirectParams))
	for name := range redirectParams {
		out = append(out, name)
	}

	sort.Strings(out)

	return out
}

// Entry is one classified injection point.
type Entry struct {
	URL string `json:"url"`
	// Kinds is why this URL is interesting, sorted for stable output.
	Kinds []Kind `json:"kinds"`
	// Params names the parameters worth attacking on this URL.
	Params []string `json:"params,omitempty"`
	// Vendor names the click-wrapper product when one was recognized.
	Vendor string `json:"vendor,omitempty"`
}

// Interesting reports whether this entry earned any classification at all.
func (e Entry) Interesting() bool {
	return len(e.Kinds) > 0
}

// Has reports whether the entry carries a kind.
func (e Entry) Has(kind Kind) bool {
	return slices.Contains(e.Kinds, kind)
}

// Classify decides what makes a URL worth a request, if anything.
func Classify(raw string) (Entry, bool) {
	normalized, ok := Normalize(raw)
	if !ok {
		return Entry{}, false
	}

	parsed, err := url.Parse(normalized)
	if err != nil {
		return Entry{}, false
	}

	entry := Entry{URL: normalized, Kinds: []Kind{}, Params: []string{}}
	kinds := map[Kind]struct{}{}

	classifyQuery(parsed, &entry, kinds)

	if hasOpaqueSegment(parsed) {
		kinds[KindPath] = struct{}{}
	}

	if vendor, hit := MatchVendor(normalized); hit {
		kinds[KindVendorSig] = struct{}{}
		entry.Vendor = vendor
	}

	entry.Kinds = sortedKinds(kinds)
	sort.Strings(entry.Params)

	return entry, entry.Interesting()
}

func classifyQuery(parsed *url.URL, entry *Entry, kinds map[Kind]struct{}) {
	seen := map[string]struct{}{}

	for key, values := range parsed.Query() {
		lower := strings.ToLower(key)

		if _, isRedirect := redirectParams[lower]; isRedirect {
			kinds[KindParamName] = struct{}{}

			addParam(entry, seen, key)
		}

		if slices.ContainsFunc(values, looksLikeDestination) {
			kinds[KindParamValue] = struct{}{}

			addParam(entry, seen, key)
		}
	}
}

func addParam(entry *Entry, seen map[string]struct{}, key string) {
	if _, dup := seen[key]; dup {
		return
	}

	seen[key] = struct{}{}
	entry.Params = append(entry.Params, key)
}

// looksLikeDestination catches a value that is already a URL, including the
// percent-encoded and protocol-relative forms.
func looksLikeDestination(value string) bool {
	if value == "" {
		return false
	}

	candidates := []string{value}
	if unescaped, err := url.QueryUnescape(value); err == nil && unescaped != value {
		candidates = append(candidates, unescaped)
	}

	for _, candidate := range candidates {
		lower := strings.ToLower(candidate)

		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			return true
		}

		if strings.HasPrefix(candidate, "//") && len(candidate) > 2 {
			return true
		}
	}

	return false
}

// hasOpaqueSegment reuses the decoder's own detector, so the classifier and
// the decoder agree on what counts as encoded state.
func hasOpaqueSegment(parsed *url.URL) bool {
	for segment := range strings.SplitSeq(parsed.EscapedPath(), "/") {
		token, err := url.PathUnescape(segment)
		if err != nil {
			continue
		}

		stripped, _ := decode.StripSuffix(token)
		if decode.IsOpaque(stripped) {
			return true
		}
	}

	return false
}

func sortedKinds(kinds map[Kind]struct{}) []Kind {
	out := make([]Kind, 0, len(kinds))
	for kind := range kinds {
		out = append(out, kind)
	}

	slices.Sort(out)

	return out
}
