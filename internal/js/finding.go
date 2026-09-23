package js

import (
	"strings"

	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/payload"
)

// mechanismJS labels a finding that came from reading client-side code.
const mechanismJS = payload.MechJS

// Findings projects a page's verdicts onto capability-scored findings.
//
// Every one is a candidate, never confirmed. Reading a bundle proves what a
// guard permits; it does not prove a browser navigated. Promotion to confirmed
// belongs to the headless stage, and claiming it here would be exactly the
// dishonesty the backUrl case study warns about.
func (p PageReport) Findings() []model.Finding {
	out := make([]model.Finding, 0, len(p.Verdicts))

	for _, v := range p.Verdicts {
		out = append(out, v.Finding(p.URL, p.validatorFor(v)))
	}

	return out
}

// validatorFor finds the guard a verdict came from, so the finding carries it.
func (p PageReport) validatorFor(v Verdict) *Validator {
	for _, r := range p.Scripts {
		for _, sink := range r.Sinks {
			if sink.Kind == v.Sink && sink.Validator != nil {
				return sink.Validator
			}
		}
	}

	return nil
}

// Finding turns one verdict into a finding rooted at source.
func (v Verdict) Finding(source string, validator *Validator) model.Finding {
	cand := model.NewNavigationCandidate(source, model.RepresentationJSExpression)
	cand.ParamName = paramFromEvidence(v.Evidence)

	if validator != nil {
		cand.Validator = validator.Model()
	}

	f := model.NewFinding()
	f.TechniqueID = v.TechniqueID
	f.Mechanism = mechanismJS
	f.Payload = v.Payload
	f.Rationale = v.Discrepancy
	f.Candidate = cand
	f.Verdict = model.VerdictCandidate

	f.Evidence = append([]string{"discrepancy: " + v.Discrepancy}, v.Evidence...)

	if v.TechniqueID == "OR-E01" {
		f.Capabilities.JavaScriptScheme = true
	}

	f.Candidate.Capabilities = f.Capabilities

	return f
}

func paramFromEvidence(evidence []string) string {
	for _, e := range evidence {
		if rest, ok := strings.CutPrefix(e, "parameter "); ok {
			return rest
		}
	}

	return ""
}
