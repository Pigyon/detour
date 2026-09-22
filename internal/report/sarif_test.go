package report_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sarifDoc mirrors the parts of SARIF 2.1.0 a consumer actually reads.
type sarifDoc struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name  string `json:"name"`
				Rules []struct {
					ID      string `json:"id"`
					HelpURI string `json:"helpUri"`
					Short   struct {
						Text string `json:"text"`
					} `json:"shortDescription"`
					DefaultConfiguration struct {
						Level string `json:"level"`
					} `json:"defaultConfiguration"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Kind    string `json:"kind"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			WebRequest *struct {
				Method string `json:"method"`
				Target string `json:"target"`
			} `json:"webRequest"`
			WebResponse *struct {
				StatusCode int               `json:"statusCode"`
				Headers    map[string]string `json:"headers"`
			} `json:"webResponse"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
		} `json:"results"`
	} `json:"runs"`
}

func sampleFindings() []model.Finding {
	a := model.NewFinding()
	a.TechniqueID = "OR-A01"
	a.Mechanism = mechQuery
	a.Payload = "https://allowed.lab@canary.invalid"
	a.Verdict = model.VerdictConfirmed
	a.ProbeURL = "https://a.lab/go?url=https%3A%2F%2Fallowed.lab%40canary.invalid"
	a.Evidence = []string{"status 302", "Location: https://allowed.lab@canary.invalid"}
	a.Candidate = model.NewNavigationCandidate("https://a.lab/go", model.RepresentationQueryParameter)
	a.Candidate.ParamName = "url"
	a.Capabilities.RedirectExternal = true
	a.Capabilities.InputControlled = true

	b := model.NewFinding()
	b.TechniqueID = "OR-C02"
	b.Mechanism = "js"
	b.Payload = "https://canary.invalid/"
	b.Verdict = model.VerdictCandidate
	b.Rationale = "sink is fed from location.hash"
	b.Candidate = model.NewNavigationCandidate("https://a.lab/page", model.RepresentationJSExpression)

	return []model.Finding{a, b}
}

func TestSARIFShape(t *testing.T) {
	t.Parallel()

	raw, err := report.SARIF(sampleFindings(), "1.2.3")
	require.NoError(t, err)

	var doc sarifDoc

	require.NoError(t, json.Unmarshal(raw, &doc))
	assert.Equal(t, "2.1.0", doc.Version)
	assert.Contains(t, doc.Schema, "sarif-schema-2.1.0")
	require.Len(t, doc.Runs, 1)
	assert.Equal(t, "detour", doc.Runs[0].Tool.Driver.Name)
	require.Len(t, doc.Runs[0].Results, 2)
}

// TestSARIFRuleCoverage is the rule and helpUri coverage check: every emitted
// ruleId resolves to a rule, and every rule points into REFERENCE.md.
func TestSARIFRuleCoverage(t *testing.T) {
	t.Parallel()

	raw, err := report.SARIF(sampleFindings(), "test")
	require.NoError(t, err)

	var doc sarifDoc

	require.NoError(t, json.Unmarshal(raw, &doc))

	rules := map[string]string{}
	for _, rule := range doc.Runs[0].Tool.Driver.Rules {
		rules[rule.ID] = rule.HelpURI

		assert.NotEmpty(t, rule.Short.Text, "%s has no description", rule.ID)
		assert.Contains(t, rule.HelpURI, "REFERENCE.md#"+strings.ToLower(rule.ID))
		assert.Contains(t, []string{"error", "warning", "note"}, rule.DefaultConfiguration.Level)
	}

	for _, result := range doc.Runs[0].Results {
		_, ok := rules[result.RuleID]
		assert.True(t, ok, "result %s has no matching rule", result.RuleID)
	}
}

// TestSARIFUsesTheDASTShape pins that a redirect finding is reported as a web
// request and response, not as a file and line that does not exist.
func TestSARIFUsesTheDASTShape(t *testing.T) {
	t.Parallel()

	raw, err := report.SARIF(sampleFindings(), "test")
	require.NoError(t, err)

	var doc sarifDoc

	require.NoError(t, json.Unmarshal(raw, &doc))

	for _, result := range doc.Runs[0].Results {
		require.Len(t, result.Locations, 1)
		assert.True(t, strings.HasPrefix(result.Locations[0].PhysicalLocation.ArtifactLocation.URI, "https://"),
			"the location is the finding URL")
		assert.NotEmpty(t, result.PartialFingerprints["detourRootCause/v1"],
			"consumers dedupe by root cause the way detour does")

		if result.RuleID == "OR-A01" {
			require.NotNil(t, result.WebRequest)
			assert.Equal(t, "GET", result.WebRequest.Method)
			require.NotNil(t, result.WebResponse)
			assert.Equal(t, 302, result.WebResponse.StatusCode)
			assert.Contains(t, result.WebResponse.Headers["Location"], "canary.invalid")
		}
	}
}

// TestSARIFKindSeparatesProvenFromCandidate keeps an unconfirmed candidate
// from reading like a proven failure.
func TestSARIFKindSeparatesProvenFromCandidate(t *testing.T) {
	t.Parallel()

	raw, err := report.SARIF(sampleFindings(), "test")
	require.NoError(t, err)

	var doc sarifDoc

	require.NoError(t, json.Unmarshal(raw, &doc))

	kinds := map[string]string{}
	for _, result := range doc.Runs[0].Results {
		kinds[result.RuleID] = result.Kind
	}

	assert.Equal(t, "fail", kinds["OR-A01"])
	assert.Equal(t, "open", kinds["OR-C02"], "a candidate is open, not failed")
}

func TestSARIFEmptyIsValid(t *testing.T) {
	t.Parallel()

	raw, err := report.SARIF(nil, "test")
	require.NoError(t, err)

	var doc sarifDoc

	require.NoError(t, json.Unmarshal(raw, &doc))
	assert.Equal(t, "2.1.0", doc.Version)
	assert.Empty(t, doc.Runs[0].Results)
}
