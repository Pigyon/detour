package report_test

import (
	"strings"
	"testing"

	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// paramURL is the destination parameter these fixtures use.
const paramURL = "url"

// mechQuery is the mechanism most report fixtures use.
const mechQuery = "query"

func TestRootCauseDedupe(t *testing.T) {
	t.Parallel()

	mk := func(url, param, technique, verdict string) model.Finding {
		f := model.NewFinding()
		f.TechniqueID = technique
		f.Mechanism = mechQuery
		f.Verdict = verdict
		f.Candidate = model.NewNavigationCandidate(url, model.RepresentationQueryParameter)
		f.Candidate.ParamName = param

		return f
	}

	findings := []model.Finding{
		mk("https://a.lab/article/1?url=x", "url", "OR-A07", model.VerdictCandidate),
		mk("https://a.lab/article/2?url=x", "url", "OR-A07", model.VerdictConfirmed),
		mk("https://a.lab/article/3?url=x", "url", "OR-A07", model.VerdictCandidate),
		mk("https://a.lab/go?url=x", "url", "OR-A07", model.VerdictConfirmed),
		mk("https://a.lab/go?url=x", "url", "OR-A01", model.VerdictConfirmed),
	}

	unique := report.Dedupe(findings)
	require.Len(t, unique, 3, "ids collapse; a different endpoint or technique does not")

	// The surviving article finding is the confirmed one, not the first seen.
	for _, f := range unique {
		if strings.Contains(f.Candidate.SourceURL, "/article/") {
			assert.Equal(t, model.VerdictConfirmed, f.Verdict, "the strongest demonstration survives")
		}
	}
}

func TestFingerprintIsStable(t *testing.T) {
	t.Parallel()

	f := model.NewFinding()
	f.TechniqueID = "OR-A07"
	f.Candidate = model.NewNavigationCandidate("https://a.lab/article/7?url=x", model.RepresentationQueryParameter)
	f.Candidate.ParamName = paramURL

	g := f
	g.Candidate = model.NewNavigationCandidate("https://a.lab/article/99?url=y", model.RepresentationQueryParameter)
	g.Candidate.ParamName = paramURL

	assert.Equal(t, report.Fingerprint(f), report.Fingerprint(g), "ids do not change the defect")
	assert.Len(t, report.Fingerprint(f), 32)
}
