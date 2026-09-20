package confirm

import (
	"net/url"
	"strings"

	"github.com/nedlir/detour/internal/model"
)

// Payload placeholders left by the JS stage, which has no canary of its own.
const (
	tokenCanary  = "{{canary}}"
	tokenTarget  = "{{target}}"
	tokenAllowed = "{{allowed}}"
)

// techniqueHash is the fragment sink. Its payload has to ride in the fragment
// because that is the whole point of the class: the server never sees it.
const techniqueHash = "OR-C02"

// notNavigable are findings a page visit cannot settle. Reverse tabnabbing is
// about window.opener, not a destination, and a sandbox-less frame is a
// precondition rather than a navigation.
var notNavigable = map[string]struct{}{
	"OR-F09": {},
	"OR-C03": {},
}

// ProbeFor builds the URL to drive in the browser for a candidate finding,
// and reports whether the finding is browser-confirmable at all.
func ProbeFor(f model.Finding, canary string) (string, bool) {
	if _, skip := notNavigable[f.TechniqueID]; skip {
		return "", false
	}

	// The attack engine already built a concrete request; replay it as is.
	if f.ProbeURL != "" {
		return f.ProbeURL, true
	}

	source := f.Candidate.SourceURL
	if source == "" || f.Payload == "" {
		return "", false
	}

	payload := expand(f, canary)

	if f.TechniqueID == techniqueHash {
		return withFragment(source, payload)
	}

	if f.Candidate.ParamName == "" {
		return "", false
	}

	return withParam(source, f.Candidate.ParamName, payload)
}

// expand fills in the placeholders the JS stage leaves behind.
func expand(f model.Finding, canary string) string {
	out := strings.ReplaceAll(f.Payload, tokenCanary, canary)
	out = strings.ReplaceAll(out, tokenTarget, hostOf(f.Candidate.SourceURL))

	return strings.ReplaceAll(out, tokenAllowed, allowedHost(f))
}

// allowedHost picks a host the finding's validator trusts, so a payload that
// has to wear one is built correctly.
func allowedHost(f model.Finding) string {
	if v := f.Candidate.Validator; v != nil && len(v.Allowlist) > 0 {
		entry := v.Allowlist[0]
		entry = strings.TrimPrefix(strings.TrimPrefix(entry, "https://"), "http://")

		if i := strings.IndexAny(entry, "/?#"); i >= 0 {
			entry = entry[:i]
		}

		return entry
	}

	return hostOf(f.Candidate.SourceURL)
}

func withParam(source, name, payload string) (string, bool) {
	parsed, err := url.Parse(source)
	if err != nil {
		return "", false
	}

	query := parsed.Query()
	query.Set(name, payload)
	parsed.RawQuery = query.Encode()

	return parsed.String(), true
}

func withFragment(source, payload string) (string, bool) {
	parsed, err := url.Parse(source)
	if err != nil {
		return "", false
	}

	parsed.Fragment = payload

	return parsed.String(), true
}
