package model_test

import (
	"encoding/json"
	"testing"

	"github.com/nedlir/detour/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepresentationStringRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rep  model.Representation
		want string
	}{
		{name: "unknown", rep: model.RepresentationUnknown, want: "unknown"},
		{name: "query", rep: model.RepresentationQueryParameter, want: "query_parameter"},
		{name: "path", rep: model.RepresentationPathSegment, want: "path_segment"},
		{name: "fragment", rep: model.RepresentationFragment, want: "fragment"},
		{name: "header", rep: model.RepresentationHeader, want: "header"},
		{name: "cookie", rep: model.RepresentationCookie, want: "cookie"},
		{name: "json body", rep: model.RepresentationJSONBody, want: "json_body"},
		{name: "form body", rep: model.RepresentationFormBody, want: "form_body"},
		{name: "opaque blob", rep: model.RepresentationOpaqueBlob, want: "opaque_blob"},
		{name: "js expression", rep: model.RepresentationJSExpression, want: "js_expression"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, tt.rep.String())

			got, ok := model.ParseRepresentation(tt.want)
			require.True(t, ok)
			assert.Equal(t, tt.rep, got)
		})
	}
}

func TestParseRepresentationUnknown(t *testing.T) {
	t.Parallel()

	got, ok := model.ParseRepresentation("not-a-representation")
	assert.False(t, ok)
	assert.Equal(t, model.RepresentationUnknown, got)
}

func TestNavigationCandidateJSONRoundTrip(t *testing.T) {
	t.Parallel()

	c := model.NewNavigationCandidate("https://target.example/go?next=https://a", model.RepresentationQueryParameter)
	c.ParamName = "next"
	c.DecoderChain = []model.Decoder{{Kind: "base64url"}, {Kind: "zlib"}, {Kind: "json"}}
	c.URLFields = []model.FieldPath{"$[4]"}
	c.Validator = &model.Validator{
		Name:      "checkBackUrlIsSafe",
		Kind:      "startsWith",
		Allowlist: []string{"https://target.example"},
	}
	c.Capabilities.RedirectExternal = true
	c.Capabilities.HopCount = 1

	raw, err := json.Marshal(c)
	require.NoError(t, err)

	var got model.NavigationCandidate
	require.NoError(t, json.Unmarshal(raw, &got))

	assert.Equal(t, c.SourceURL, got.SourceURL)
	assert.Equal(t, c.Representation, got.Representation)
	assert.Equal(t, c.ParamName, got.ParamName)
	assert.Equal(t, c.DecoderChain, got.DecoderChain)
	assert.Equal(t, c.URLFields, got.URLFields)
	require.NotNil(t, got.Validator)
	assert.Equal(t, c.Validator.Name, got.Validator.Name)
	assert.Equal(t, c.Validator.Allowlist, got.Validator.Allowlist)
	assert.True(t, got.Capabilities.RedirectExternal)
	assert.Equal(t, 1, got.Capabilities.HopCount)
}

func TestNavigationCandidateCloneIsIndependent(t *testing.T) {
	t.Parallel()

	orig := model.NewNavigationCandidate("https://t.example/", model.RepresentationOpaqueBlob)
	orig.DecoderChain = []model.Decoder{{Kind: "json"}}
	orig.URLFields = []model.FieldPath{"$.dest"}
	orig.Validator = &model.Validator{Allowlist: []string{"t.example"}}

	cloned := orig.Clone()
	cloned.DecoderChain[0].Kind = "xml"
	cloned.URLFields[0] = "$.other"
	cloned.Validator.Allowlist[0] = "evil.example"

	assert.Equal(t, "json", orig.DecoderChain[0].Kind)
	assert.Equal(t, model.FieldPath("$.dest"), orig.URLFields[0])
	assert.Equal(t, "t.example", orig.Validator.Allowlist[0])
}

func TestCapabilitySetMerge(t *testing.T) {
	t.Parallel()

	a := model.CapabilitySet{RedirectExternal: true, HopCount: 1}
	b := model.CapabilitySet{InputControlled: true, HopCount: 3, OAuthRedirectURI: true}

	got := a.Merge(b)
	assert.True(t, got.RedirectExternal)
	assert.True(t, got.InputControlled)
	assert.True(t, got.OAuthRedirectURI)
	assert.Equal(t, 3, got.HopCount)
	assert.False(t, a.InputControlled)
}

func TestNewFindingSchemaVersion(t *testing.T) {
	t.Parallel()

	f := model.NewFinding()
	assert.Equal(t, model.FindingSchemaVersion, f.SchemaVersion)
	require.NotNil(t, f.Evidence)
	assert.Empty(t, f.Evidence)
}
