package confirm

import (
	"net/url"
	"sort"
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

// ProbesFor builds the URLs worth driving in the browser for a candidate
// finding, and reports whether the finding is browser-confirmable at all.
//
// Usually one. When the JS stage traced a sink's input to a concrete query
// parameter, that is the only one worth trying. When it could not (the
// value passed through an expression the tracer gives up on), there is
// still something to try: every query parameter the source URL already
// carries, in case one of them is the untraced path to the sink. A wrong
// guess here can never produce a false confirmation, since a browser visit
// still has to prove the destination was actually reached; the only cost of
// guessing wrong is a visit that finds nothing, same as not guessing at all.
func ProbesFor(f model.Finding, canary string) []string {
	if _, skip := notNavigable[f.TechniqueID]; skip {
		return nil
	}

	// The attack engine already built a concrete request; replay it as is.
	if f.ProbeURL != "" {
		return []string{f.ProbeURL}
	}

	source := f.Candidate.SourceURL
	if source == "" || f.Payload == "" {
		return nil
	}

	payload := expand(f, canary)

	if f.TechniqueID == techniqueHash {
		if u, ok := withFragment(source, payload); ok {
			return []string{u}
		}

		return nil
	}

	if f.Candidate.ParamName != "" {
		if u, ok := withParam(source, f.Candidate.ParamName, payload); ok {
			return []string{u}
		}

		return nil
	}

	return guessedParamProbes(source, payload)
}

// guessedParamProbes tries every query parameter already on source, sorted
// for a deterministic attempt order across runs.
func guessedParamProbes(source, payload string) []string {
	parsed, err := url.Parse(source)
	if err != nil {
		return nil
	}

	query := parsed.Query()
	names := make([]string, 0, len(query))

	for name := range query {
		names = append(names, name)
	}

	sort.Strings(names)

	out := make([]string, 0, len(names))

	for _, name := range names {
		if u, ok := withParam(source, name, payload); ok {
			out = append(out, u)
		}
	}

	return out
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
