package report_test

import (
	"strings"
	"testing"

	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/report"
	"github.com/stretchr/testify/assert"
)

// blobFinding is the shape the decoder produces: a destination that is not
// visible anywhere in the URL.
func blobFinding() model.Finding {
	f := model.NewFinding()
	f.TechniqueID = "OR-B01"
	f.Mechanism = "blob"
	f.ProbeURL = "https://t.example/click/AAAA.html"
	f.Repro = "curl -sI 'https://t.example/click/AAAA.html'"
	f.Candidate.SourceURL = "https://t.example/click/BBBB.html"
	f.Candidate.DecoderChain = []model.Decoder{{Kind: "base64:url"}, {Kind: "zlib"}, {Kind: "json"}}
	f.Evidence = []string{
		"status 302",
		"Location: https://canary.invalid",
		"blob_field=$[4]",
		"blob_strategy=preserved-envelope",
	}

	return f
}

// TestRenderExplainsTheEnvelope is what makes a blob finding submittable.
//
// Without it the report is two opaque base64 strings and an assurance that
// the second is the first with the destination swapped, which is not
// something a triager can check.
func TestRenderExplainsTheEnvelope(t *testing.T) {
	t.Parallel()

	out := report.Render(blobFinding())

	assert.Contains(t, out, "## Inside the envelope")
	assert.Contains(t, out, "`base64:url` then `zlib` then `json`",
		"the chain has to be named in the order it is applied")
	assert.Contains(t, out, "`$[4]`", "and the field the destination sits in")
	assert.Contains(t, out, "detour decode", "with a way to check it by hand")
	assert.Contains(t, out, "only change is the destination",
		"a preserved envelope is the difference between a proof and a broken link")
}

// TestRenderLeavesPlainFindingsAlone keeps the section off the findings that
// have no envelope, where it would be noise.
func TestRenderLeavesPlainFindingsAlone(t *testing.T) {
	t.Parallel()

	f := model.NewFinding()
	f.TechniqueID = techA01
	f.Mechanism = "query"
	f.Candidate.SourceURL = "https://t.example/go?url=x"
	f.Evidence = []string{"status 302", "Location: https://canary.invalid"}

	out := report.Render(f)

	assert.NotContains(t, out, "Inside the envelope")
	assert.NotContains(t, out, "detour decode")
}

// TestRenderIsFreeOfEmDashes holds the house rule at the one place it reaches
// somebody else: a report that gets submitted.
func TestRenderIsFreeOfEmDashes(t *testing.T) {
	t.Parallel()

	assert.NotContains(t, report.Render(blobFinding()), "—")
}

func TestRenderNamesTheParameter(t *testing.T) {
	t.Parallel()

	f := blobFinding()
	f.Candidate.ParamName = "next"

	assert.Contains(t, strings.SplitN(report.Render(f), "\n", 2)[0], "next")
}
