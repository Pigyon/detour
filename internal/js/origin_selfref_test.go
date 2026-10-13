package js_test

import (
	"testing"

	"github.com/nedlir/detour/internal/js"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSelfLocationSinkIsNotAnOpenRedirect is a regression for a false positive:
// a local named like a redirect parameter but assigned the whole current
// location was misread as an attacker-controlled query source. The destination
// is the current page, so it is self-navigation, not an open redirect.
//
// This mirrors tax.audible.com's loadTaxportalByLang.
func TestSelfLocationSinkIsNotAnOpenRedirect(t *testing.T) {
	t.Parallel()

	code := `function loadTaxportalByLang(value){
		var uri = window.location.toString();
		if (uri.indexOf("?") > 0) {
			location.href = new URL(uri.substring(0, uri.indexOf("?"))).toString();
		}
	}`

	report, err := js.Analyze("t.js", []byte(code))
	require.NoError(t, err)
	require.Len(t, report.Sinks, 1)
	assert.Equal(t, js.OriginSelf, report.Sinks[0].Origin.Kind,
		"a value read from window.location is self-referential, not query input")
	assert.Empty(t, report.Verdicts, "self-navigation must not be reported as an open redirect")
}

func TestWholeLocationReadsAreSelf(t *testing.T) {
	t.Parallel()

	for _, code := range []string{
		`location.href = window.location.href`,
		`location.assign(document.URL)`,
		`var u = location.href; location.href = u`,
	} {
		report, err := js.Analyze("t.js", []byte(code))
		require.NoError(t, err)
		assert.Empty(t, report.Verdicts, "self-location destination should yield no verdict: %s", code)
	}
}

func TestConstantDestinationIsNotAnOpenRedirect(t *testing.T) {
	t.Parallel()

	for _, code := range []string{
		`location.href = 'https://go.microsoft.com/fwlink/?linkid=2135547'`,
		`var dest = "https://example.com/fixed"; location.href = dest`,
	} {
		report, err := js.Analyze("t.js", []byte(code))
		require.NoError(t, err)
		assert.Empty(t, report.Verdicts, "a constant destination is not attacker-controlled: %s", code)
	}
}

// TestControllableSinksStillFire guards against over-suppression: a genuine
// query-fed or untraced sink must still be reported.
func TestControllableSinksStillFire(t *testing.T) {
	t.Parallel()

	for _, code := range []string{
		`location.href = new URLSearchParams(location.search).get('next')`,
		`function g(u){ location.href = u }`,
		`var n = location.search; location.href = n`,
	} {
		report, err := js.Analyze("t.js", []byte(code))
		require.NoError(t, err)
		assert.NotEmpty(t, report.Verdicts, "a controllable or untraced sink must still be reported: %s", code)
	}
}
