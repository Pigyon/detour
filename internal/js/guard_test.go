package js_test

import (
	"testing"

	"github.com/nedlir/detour/internal/js"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// checkBackUrlIsSafe is the guard from cases/kucoin-backurl-dead-end.md,
// transcribed as it appears in the bundle. It is the reference fixture for
// two reasons: it is attached to an object rather than declared, and the
// navigation it protects is several steps away from it.
// hostALab is the trusted host across the guard fixtures.
const hostALab = "a.lab"

const checkBackURLIsSafeBundle = `
e.checkBackUrlIsSafe=function(e){
  if(!e||!b)return!1;
  const t=(()=>{try{return decodeURIComponent(decodeURIComponent(e))}catch{return null}})();
  if(!t||/javascript/i.test(t))return!1;
  let n; try{n=new URL(e)}catch{return!1}
  if("http:"!==n.protocol&&"https:"!==n.protocol)return!1;
  if(n.username||n.password)return!1;
  const {hostname:h}=window.location, r=m()?.safeDomains??[];
  return (h?[...r,h]:r).some(e=>n.hostname===e);
};
function onLogin(backUrl, back, fallback){
  const r = backUrl ? (checkBackUrlIsSafe(backUrl)?backUrl:fallback)
          : back ? (checkBackUrlIsSafe(back)?back:fallback) : fallback;
  window.location.href = r;
}
`

// TestGuardReadsCheckBackUrlIsSafe reproduces the human analysis of the real
// bundle. The guard is never matched by name: searching for allowList or
// whitelist is exactly what missed it in the first place.
func TestGuardReadsCheckBackUrlIsSafe(t *testing.T) {
	t.Parallel()

	report, err := js.Analyze("bundle.js", []byte(checkBackURLIsSafeBundle))
	require.NoError(t, err)
	require.Len(t, report.Sinks, 1)

	sink := report.Sinks[0]
	assert.Equal(t, js.SinkLocationHref, sink.Kind)
	assert.Equal(t, "backUrl", sink.Origin.Param, "the request parameter, not the local that carries it")
	require.NotNil(t, sink.Validator)

	v := *sink.Validator
	assert.Equal(t, "checkBackUrlIsSafe", v.Name)
	assert.Equal(t, js.MatchEquality, v.Kind, "exact hostname equality, not the javascript regex")
	assert.Equal(t, "safeDomains", v.AllowlistRef, "the list is not in this file")
	assert.True(t, v.ChecksScheme)
	assert.True(t, v.ChecksUserinfo)
	assert.True(t, v.BlocksJavaScript)
	assert.True(t, v.AllowsHTTP, "the allowlist permits http, which is the residual")
	assert.Equal(t, 2, v.DecodeCount, "decodes twice, so there is no double-decode gap")
	assert.True(t, v.Resolved)
}

// TestVerdictsOnCheckBackUrlIsSafe is the conclusion the case study reached by
// hand: not a finding, with one residual. Anything more would be a false
// positive on a guard that is actually correct.
func TestVerdictsOnCheckBackUrlIsSafe(t *testing.T) {
	t.Parallel()

	report, err := js.Analyze("bundle.js", []byte(checkBackURLIsSafeBundle))
	require.NoError(t, err)
	require.Len(t, report.Verdicts, 1)

	only := report.Verdicts[0]
	assert.Equal(t, "OR-E03", only.TechniqueID)
	assert.Equal(t, js.SeverityInfo, only.Severity)
	assert.Contains(t, only.Discrepancy, "downgrade")
}

func TestGuardExtraction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		code          string
		wantKind      string
		wantAllowlist []string
		wantScheme    bool
		wantUserinfo  bool
		wantDecodes   int
	}{
		{
			name:          "prefix match on a literal array",
			code:          `function ok(u){ return ["a.lab"].some(d => u.startsWith(d)) } function g(u){ if (ok(u)) location.href = u }`,
			wantKind:      js.MatchPrefix,
			wantAllowlist: []string{hostALab},
		},
		{
			name:          "suffix match on a named constant",
			code:          `const hosts = ["a.lab","b.lab"]; function ok(u){ return hosts.some(d => u.hostname.endsWith(d)) } function g(u){ if (ok(u)) location.href = u }`,
			wantKind:      js.MatchSuffix,
			wantAllowlist: []string{hostALab, "b.lab"},
		},
		{
			name:          "substring match keeps the literal it compares against",
			code:          `function ok(u){ return u.includes("a.lab") } function g(u){ if (ok(u)) location.href = u }`,
			wantKind:      js.MatchSubstring,
			wantAllowlist: []string{hostALab},
		},
		{
			name:          "array membership is equality",
			code:          `const hosts = ["a.lab"]; function ok(u){ return hosts.includes(new URL(u).hostname) } function g(u){ if (ok(u)) location.href = u }`,
			wantKind:      js.MatchEquality,
			wantAllowlist: []string{hostALab},
		},
		{
			name:         "scheme and userinfo checks are seen",
			code:         `function ok(u){ const p = new URL(u); return p.protocol === "https:" && !p.username && !p.password && p.hostname === "a.lab" } function g(u){ if (ok(u)) location.href = u }`,
			wantKind:     js.MatchEquality,
			wantScheme:   true,
			wantUserinfo: true,
		},
		{
			name:          "single decode is counted",
			code:          `function ok(u){ return decodeURIComponent(u).startsWith("https://a.lab") } function g(u){ if (ok(u)) location.href = u }`,
			wantKind:      js.MatchPrefix,
			wantAllowlist: []string{"https://a.lab"},
			wantDecodes:   1,
			wantScheme:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			report, err := js.Analyze("t.js", []byte(tt.code))
			require.NoError(t, err)
			require.Len(t, report.Sinks, 1)
			require.NotNil(t, report.Sinks[0].Validator)

			v := *report.Sinks[0].Validator
			assert.Equal(t, tt.wantKind, v.Kind)
			assert.Equal(t, tt.wantAllowlist, v.Allowlist)
			assert.Equal(t, tt.wantScheme, v.ChecksScheme)
			assert.Equal(t, tt.wantUserinfo, v.ChecksUserinfo)
			assert.Equal(t, tt.wantDecodes, v.DecodeCount)
		})
	}
}

// TestGuardUnresolvedIsNotTreatedAsAbsent keeps "guarded by something detour
// cannot read" distinct from "not guarded at all".
func TestGuardUnresolvedIsNotTreatedAsAbsent(t *testing.T) {
	t.Parallel()

	report, err := js.Analyze("t.js", []byte(`function g(u){ if (imported.isSafe(u)) { location.href = u } }`))
	require.NoError(t, err)
	require.Len(t, report.Sinks, 1)
	require.NotNil(t, report.Sinks[0].Validator)
	assert.False(t, report.Sinks[0].Validator.Resolved)

	require.Len(t, report.Verdicts, 1)
	assert.Equal(t, js.SeverityInfo, report.Verdicts[0].Severity)
	assert.Contains(t, report.Verdicts[0].Discrepancy, "not in this script")
}

func TestValidatorModel(t *testing.T) {
	t.Parallel()

	report, err := js.Analyze("t.js", []byte(
		`const hosts = ["a.lab"]; function ok(u){ return hosts.some(d => u.endsWith(d)) } function g(u){ if (ok(u)) location.href = u }`,
	))
	require.NoError(t, err)

	cands := report.Candidates()
	require.Len(t, cands, 1)
	require.NotNil(t, cands[0].Validator)
	assert.Equal(t, "ok", cands[0].Validator.Name)
	assert.Equal(t, "js", cands[0].Validator.Source)
	assert.Equal(t, js.MatchSuffix, cands[0].Validator.Kind)
	assert.Equal(t, []string{hostALab}, cands[0].Validator.Allowlist)
}
