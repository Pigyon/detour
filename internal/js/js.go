// Package js finds navigation sinks in client-side code, traces each one back
// to the guard that is supposed to protect it, and reports what that guard
// actually treats as safe.
//
// The guiding lesson is from the KuCoin backUrl dead end in cases/: searching
// for allowList or whitelist missed checkBackUrlIsSafe entirely. Every guard
// here is recognized structurally, by what it does to a host, never by name.
package js

import (
	"fmt"

	"github.com/nedlir/detour/internal/model"
	"github.com/tdewolff/parse/v2"
	tdjs "github.com/tdewolff/parse/v2/js"
)

// Report is everything one script yielded.
type Report struct {
	Source     string      `json:"source"`
	Sinks      []Sink      `json:"sinks"`
	Validators []Validator `json:"validators,omitempty"`
	Verdicts   []Verdict   `json:"verdicts,omitempty"`
	URLs       []string    `json:"urls,omitempty"`
}

// Analyze parses code and reports its navigation sinks, the guards protecting
// them, and what those guards let through. A parse error is returned rather
// than guessed at: a half-parsed bundle produces dishonest findings.
func Analyze(source string, code []byte) (Report, error) {
	ast, err := tdjs.Parse(parse.NewInputBytes(code), tdjs.Options{})
	if err != nil {
		return Report{}, fmt.Errorf("parsing %s: %w", source, err)
	}

	sc := &scanner{
		funcs:    collectFunctions(ast),
		consts:   collectStringArrays(ast),
		bindings: collectBindings(ast),
		sinks:    []Sink{},
	}
	tdjs.Walk(&visitor{scan: sc}, ast)

	report := Report{
		Source:     source,
		Sinks:      sc.sinks,
		Validators: []Validator{},
		Verdicts:   []Verdict{},
		URLs:       collectURLs(ast),
	}

	seen := map[string]struct{}{}

	for _, sink := range report.Sinks {
		if sink.Validator != nil {
			if _, dup := seen[sink.Validator.Name]; !dup {
				seen[sink.Validator.Name] = struct{}{}

				report.Validators = append(report.Validators, *sink.Validator)
			}
		}

		report.Verdicts = append(report.Verdicts, verdictsFor(sink)...)
	}

	return report, nil
}

// Candidates projects the report onto NavigationCandidates so a JS expression
// flows through the same pipeline as a query parameter or an opaque blob.
func (r Report) Candidates() []model.NavigationCandidate {
	out := make([]model.NavigationCandidate, 0, len(r.Sinks))

	for _, sink := range r.Sinks {
		cand := model.NewNavigationCandidate(r.Source, model.RepresentationJSExpression)
		cand.ParamName = sink.Origin.Param

		if sink.Validator != nil {
			cand.Validator = sink.Validator.Model()
		}

		out = append(out, cand)
	}

	return out
}
