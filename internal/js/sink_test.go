package js_test

import (
	"testing"

	"github.com/nedlir/detour/internal/js"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnalyzeFindsSinks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		code     string
		wantKind string
		wantExpr string
	}{
		{name: "location.href assignment", code: `location.href = u`, wantKind: js.SinkLocationHref, wantExpr: "u"},
		{name: "window.location.href", code: `window.location.href = u`, wantKind: js.SinkLocationHref, wantExpr: "u"},
		{name: "bare location assignment", code: `location = u`, wantKind: js.SinkLocationHref, wantExpr: "u"},
		{name: "document.location", code: `document.location = u`, wantKind: js.SinkDocumentLocation, wantExpr: "u"},
		{name: "top.location", code: `top.location = u`, wantKind: js.SinkTopLocation, wantExpr: "u"},
		{name: "location.assign", code: `location.assign(u)`, wantKind: js.SinkLocationAssign, wantExpr: "u"},
		{name: "location.replace", code: `window.location.replace(u)`, wantKind: js.SinkLocationReplace, wantExpr: "u"},
		{name: "window.open", code: `window.open(u)`, wantKind: js.SinkWindowOpen, wantExpr: "u"},
		{name: "router.push", code: `router.push(u)`, wantKind: js.SinkRouterPush, wantExpr: "u"},
		{name: "vue style $router", code: `this.$router.replace(u)`, wantKind: js.SinkRouterReplace, wantExpr: "u"},
		{name: "computed member", code: `window["location"]["href"] = u`, wantKind: js.SinkLocationHref, wantExpr: "u"},
		{name: "inside arrow function", code: `const f = () => { location.href = u }`, wantKind: js.SinkLocationHref, wantExpr: "u"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			report, err := js.Analyze("t.js", []byte(tt.code))
			require.NoError(t, err)
			require.Len(t, report.Sinks, 1)
			assert.Equal(t, tt.wantKind, report.Sinks[0].Kind)
			assert.Equal(t, tt.wantExpr, report.Sinks[0].Expression)
		})
	}
}

func TestAnalyzeIgnoresNonSinks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		code string
	}{
		{name: "reading location is not navigating", code: `const u = location.href`},
		{name: "unrelated assign", code: `Object.assign(target, source)`},
		{name: "unrelated open", code: `db.open(name)`},
		{name: "unrelated push", code: `items.push(value)`},
		{name: "similar identifier", code: `myLocation.href = u`},
		{name: "empty", code: ``},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			report, err := js.Analyze("t.js", []byte(tt.code))
			require.NoError(t, err)
			assert.Empty(t, report.Sinks)
		})
	}
}

func TestAnalyzeTracksGuards(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		code       string
		wantGuards int
	}{
		{
			name:       "if statement guards its body",
			code:       `function g(u){ if (ok(u)) { location.href = u } }`,
			wantGuards: 1,
		},
		{
			name:       "condition itself is not guarded",
			code:       `function g(u){ if (location.href = u) { x() } }`,
			wantGuards: 0,
		},
		{
			name:       "short circuit guards the right side",
			code:       `function g(u){ ok(u) && (location.href = u) }`,
			wantGuards: 1,
		},
		{
			name:       "ternary guards its branches",
			code:       `function g(u){ ok(u) ? location.assign(u) : null }`,
			wantGuards: 1,
		},
		{
			name:       "else branch records the negation",
			code:       `function g(u){ if (bad(u)) { x() } else { location.href = u } }`,
			wantGuards: 1,
		},
		{
			name:       "unguarded",
			code:       `function g(u){ location.href = u }`,
			wantGuards: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			report, err := js.Analyze("t.js", []byte(tt.code))
			require.NoError(t, err)
			require.Len(t, report.Sinks, 1)
			assert.Len(t, report.Sinks[0].Guards, tt.wantGuards)
			assert.Equal(t, tt.wantGuards > 0, report.Sinks[0].Guarded())
		})
	}
}

// TestAnalyzeScopesBindings pins the bug a name-keyed binding table hides:
// minified bundles reuse one letter in every scope, so resolution has to
// follow the parser's resolved variable, not its name.
func TestAnalyzeScopesBindings(t *testing.T) {
	t.Parallel()

	code := `
function unrelated(){ const r = harmless(); return r }
function nav(u){ const r = ok(u) ? u : "/"; location.href = r }`

	report, err := js.Analyze("t.js", []byte(code))
	require.NoError(t, err)
	require.Len(t, report.Sinks, 1)
	assert.Equal(t, []string{"(ok(u))"}, report.Sinks[0].Guards)
}

func FuzzAnalyze(f *testing.F) {
	f.Add(`location.href = u`)
	f.Add(`function g(u){ if (ok(u)) { location.assign(u) } }`)
	f.Add(`const a = ["x"]; a.some(d => h.endsWith(d))`)
	f.Add(``)
	f.Add(`{{{{{`)
	f.Add("\x00\xff")

	f.Fuzz(func(t *testing.T, code string) {
		report, err := js.Analyze("fuzz.js", []byte(code))
		if err != nil {
			return
		}

		for _, sink := range report.Sinks {
			assert.NotEmpty(t, sink.Kind)
		}

		for _, v := range report.Verdicts {
			assert.NotEmpty(t, v.TechniqueID)
			assert.NotEmpty(t, v.Severity)
		}

		// Candidates must never outnumber the evidence they came from.
		assert.LessOrEqual(t, len(report.Candidates()), len(report.Sinks))
	})
}
