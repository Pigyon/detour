package js_test

import (
	"strings"
	"testing"

	"github.com/nedlir/detour/internal/js"
	"github.com/nedlir/detour/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pageURL is the page every synthetic report is rooted at.
const pageURL = "https://site.lab/app"

func TestVerdictsAttackTheAllowlist(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		code        string
		wantID      string
		wantPayload string
	}{
		{
			name:        "unanchored prefix",
			code:        `const h=["a.lab"]; function ok(u){return h.some(d=>new URL(u).hostname.startsWith(d))} function g(u){if(ok(u))location.href=u}`,
			wantID:      "OR-A09",
			wantPayload: "https://a.lab.{{canary}}/",
		},
		{
			name:        "unanchored suffix",
			code:        `const h=["a.lab"]; function ok(u){return h.some(d=>new URL(u).hostname.endsWith(d))} function g(u){if(ok(u))location.href=u}`,
			wantID:      "OR-A13",
			wantPayload: "https://{{canary}}.a.lab/",
		},
		{
			name:        "substring over the whole url",
			code:        `function ok(u){return u.includes("a.lab")} function g(u){if(ok(u))location.href=u}`,
			wantID:      "OR-A08",
			wantPayload: "https://{{canary}}/?a.lab",
		},
		{
			name:        "single decode gap",
			code:        `const h=["a.lab"]; function ok(u){return h.includes(new URL(decodeURIComponent(u)).hostname)} function g(u){if(ok(u))location.href=u}`,
			wantID:      "OR-B04",
			wantPayload: "https%3A%2F%2F{{canary}}%2F",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			report, err := js.Analyze("t.js", []byte(tt.code))
			require.NoError(t, err)

			v, ok := verdictByID(report.Verdicts, tt.wantID)
			require.True(t, ok, "missing %s in %v", tt.wantID, ids(report.Verdicts))
			assert.Equal(t, js.SeverityCandidate, v.Severity)
			assert.Equal(t, tt.wantPayload, v.Payload)
			assert.NotEmpty(t, v.Discrepancy, "every verdict names its discrepancy")
		})
	}
}

// TestCorrectGuardProducesNoCandidates is the zero false positive rule for
// static analysis: a guard that does the right thing must not be reported.
func TestCorrectGuardProducesNoCandidates(t *testing.T) {
	t.Parallel()

	code := `
const allowed = ["a.lab"];
function isSafe(raw){
  if(!raw) return false;
  if(/^javascript:/i.test(raw)) return false;
  let u; try { u = new URL(raw) } catch (e) { return false }
  if(u.protocol !== "https:") return false;
  if(u.username || u.password) return false;
  return allowed.some(d => u.hostname === d);
}
function go(next){ if(isSafe(next)){ location.assign(next) } }`

	report, err := js.Analyze("safe.js", []byte(code))
	require.NoError(t, err)
	require.Len(t, report.Sinks, 1)
	assert.Empty(t, report.Verdicts, "a correct guard yields nothing, got %v", ids(report.Verdicts))
}

func TestUnguardedSinkVerdicts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		code   string
		wantID string
	}{
		{name: "plain sink", code: `function g(u){ location.href = u }`, wantID: "OR-C01"},
		{name: "hash sink", code: `location.href = location.hash.slice(1)`, wantID: "OR-C02"},
		{name: "framed top navigation", code: `top.location = u`, wantID: "OR-C03"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			report, err := js.Analyze("t.js", []byte(tt.code))
			require.NoError(t, err)
			require.Len(t, report.Verdicts, 1)
			assert.Equal(t, tt.wantID, report.Verdicts[0].TechniqueID)
			assert.Equal(t, js.SeverityCandidate, report.Verdicts[0].Severity)
		})
	}
}

// TestFindingsAreAlwaysCandidates pins the honesty rule: reading a bundle
// never proves a browser navigated.
func TestFindingsAreAlwaysCandidates(t *testing.T) {
	t.Parallel()

	report, err := js.Analyze("t.js", []byte(`function g(u){ location.href = u }`))
	require.NoError(t, err)

	page := js.PageReport{URL: pageURL, Scripts: []js.Report{report}, Verdicts: report.Verdicts}

	findings := page.Findings()
	require.NotEmpty(t, findings)

	for _, f := range findings {
		assert.Equal(t, model.VerdictCandidate, f.Verdict)
		assert.Equal(t, "js", f.Mechanism)
		assert.Equal(t, model.RepresentationJSExpression, f.Candidate.Representation)
		assert.False(t, f.Capabilities.RedirectExternal, "static reading never proves a redirect")
		assert.False(t, f.Capabilities.BrowserConfirmed)
		assert.NotEmpty(t, f.Rationale, "the discrepancy is the rationale")
		assert.True(t, strings.HasPrefix(f.Evidence[0], "discrepancy: "))
	}
}

func TestJavaScriptSchemeCapability(t *testing.T) {
	t.Parallel()

	report, err := js.Analyze("t.js", []byte(`function ok(u){return u.length>0} function g(u){if(ok(u))location.href=u}`))
	require.NoError(t, err)

	page := js.PageReport{URL: pageURL, Scripts: []js.Report{report}, Verdicts: report.Verdicts}

	var found bool

	for _, f := range page.Findings() {
		if f.TechniqueID == "OR-E01" {
			found = true

			assert.True(t, f.Capabilities.JavaScriptScheme)
		}
	}

	assert.True(t, found, "a guard with no scheme check earns the javascript scheme capability")
}

func verdictByID(verdicts []js.Verdict, id string) (js.Verdict, bool) {
	for _, v := range verdicts {
		if v.TechniqueID == id {
			return v, true
		}
	}

	return js.Verdict{}, false
}

func ids(verdicts []js.Verdict) []string {
	out := make([]string, 0, len(verdicts))
	for _, v := range verdicts {
		out = append(out, v.TechniqueID)
	}

	return out
}
