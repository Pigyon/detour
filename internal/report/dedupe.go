package report

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/nedlir/detour/internal/model"
)

// idSegment matches the path components that vary per request rather than per
// endpoint.
var idSegment = regexp.MustCompile(`^(\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{36})$`)

// RootCause identifies the defect behind a finding, so two reports of the same
// broken validator collapse into one.
//
// Deduping by URL is the wrong axis and produces the reports triagers hate: a
// hundred entries for one endpoint because a hundred payloads worked, or one
// entry per article id. The defect is the host, the endpoint shape, the
// parameter, and the technique. Everything else is a demonstration of it.
func RootCause(f model.Finding) string {
	parsed, err := url.Parse(f.Candidate.SourceURL)
	if err != nil {
		return f.TechniqueID + "|" + f.Candidate.SourceURL
	}

	segments := strings.Split(parsed.EscapedPath(), "/")
	for i, segment := range segments {
		if idSegment.MatchString(segment) {
			segments[i] = "{id}"
		}
	}

	return strings.Join([]string{
		strings.ToLower(parsed.Hostname()),
		strings.Join(segments, "/"),
		strings.ToLower(f.Candidate.ParamName),
		f.TechniqueID,
		f.Mechanism,
	}, "|")
}

// Fingerprint is the stable hash of a root cause, for SARIF consumers that
// dedupe the way detour does.
func Fingerprint(f model.Finding) string {
	sum := sha256.Sum256([]byte(RootCause(f)))

	return hex.EncodeToString(sum[:16])
}

// Dedupe collapses findings that share a root cause, keeping the strongest
// demonstration of each.
//
// The survivor is the one a triager should read: confirmed beats candidate,
// and a browser-confirmed finding beats a server-side one, because that is the
// evidence that settles an argument.
func Dedupe(findings []model.Finding) []model.Finding {
	best := map[string]model.Finding{}
	order := []string{}

	for _, f := range findings {
		cause := RootCause(f)

		current, seen := best[cause]
		if !seen {
			best[cause] = f
			order = append(order, cause)

			continue
		}

		if stronger(f, current) {
			best[cause] = f
		}
	}

	out := make([]model.Finding, 0, len(order))

	for _, cause := range order {
		out = append(out, best[cause])
	}

	return out
}

// stronger reports whether a is better evidence than b.
func stronger(a, b model.Finding) bool {
	return evidenceRank(a) > evidenceRank(b)
}

func evidenceRank(f model.Finding) int {
	rank := 0

	if f.Verdict == model.VerdictConfirmed {
		rank += 4
	}

	if f.Capabilities.BrowserConfirmed {
		rank += 2
	}

	if f.Capabilities.InputControlled {
		rank++
	}

	return rank
}

// Causes groups findings by root cause, for a report that wants to show the
// other demonstrations under each defect.
func Causes(findings []model.Finding) map[string][]model.Finding {
	out := map[string][]model.Finding{}

	for _, f := range findings {
		cause := RootCause(f)
		out[cause] = append(out[cause], f)
	}

	return out
}

// TechniqueIDs lists the distinct techniques in a finding set, sorted.
func TechniqueIDs(findings []model.Finding) []string {
	seen := map[string]struct{}{}

	for _, f := range findings {
		if f.TechniqueID != "" {
			seen[f.TechniqueID] = struct{}{}
		}
	}

	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}

	sort.Strings(out)

	return out
}
