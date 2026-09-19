package attack_test

import (
	"context"
	"testing"

	"github.com/nedlir/detour/internal/lab"
	"github.com/nedlir/detour/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttackFindsOpaqueBlobs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		probe     func(*testing.T, string) string
		want      string
		wantChain []model.Decoder
		wantField model.FieldPath
	}{
		{
			name:      "compressed click wrapper in a path segment",
			probe:     clickProbe,
			want:      "OR-B01",
			wantChain: []model.Decoder{{Kind: "base64:url"}, {Kind: "zlib"}, {Kind: "json"}},
			wantField: "$[4]",
		},
		{
			name:      "unsigned wrapper in a query value",
			probe:     upnProbe,
			want:      "OR-B02",
			wantChain: []model.Decoder{{Kind: "base64:url"}, {Kind: "json"}},
			wantField: "$.url",
		},
		{
			name:      "unverified jwt claim",
			probe:     jwtProbe,
			want:      "OR-B03",
			wantChain: []model.Decoder{{Kind: "jwt"}},
			wantField: "$.redirect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			eng, srv := newEngine(t)

			findings, err := eng.Run(context.Background(), []string{tt.probe(t, srv.URL)})
			require.NoError(t, err)
			require.NotEmpty(t, findings)

			got, ok := findingByTechnique(findings, tt.want)
			require.True(t, ok, "missing %s", tt.want)

			assert.Equal(t, "blob", got.Mechanism)
			assert.Equal(t, model.VerdictConfirmed, got.Verdict)
			assert.Equal(t, model.RepresentationOpaqueBlob, got.Candidate.Representation)
			assert.Equal(t, tt.wantChain, got.Candidate.DecoderChain)
			assert.Contains(t, got.Candidate.URLFields, tt.wantField)
			assert.Contains(t, got.Evidence, "blob_field="+string(tt.wantField))
			assert.True(t, got.Capabilities.InputControlled)
			assert.True(t, got.Capabilities.RedirectExternal)
		})
	}
}

// TestAttackIgnoresVerifiedBlob is the decoder's half of the zero false
// positive gate: an envelope whose signature is checked stays silent, however
// cleanly detour can take it apart.
func TestAttackIgnoresVerifiedBlob(t *testing.T) {
	t.Parallel()

	eng, srv := newEngine(t)
	signed := lab.SignDest("https://" + lab.AllowedHost + "/home")

	findings, err := eng.Run(context.Background(), []string{srv.URL + "/decoy/signed/" + signed})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestAttackFindsDoubleEncodedParameter(t *testing.T) {
	t.Parallel()

	eng, srv := newEngine(t)

	findings, err := eng.Run(context.Background(), []string{srv.URL + "/b04?next=/account"})
	require.NoError(t, err)

	got, ok := findingByTechnique(findings, "OR-B04")
	require.True(t, ok, "missing OR-B04")
	assert.Equal(t, "query", got.Mechanism)
	assert.Equal(t, "next", got.Candidate.ParamName)
}

func findingByTechnique(findings []model.Finding, id string) (model.Finding, bool) {
	for _, f := range findings {
		if f.TechniqueID == id {
			return f, true
		}
	}

	return model.Finding{}, false
}

func clickProbe(t *testing.T, base string) string {
	t.Helper()

	blob, err := lab.EncodeClick("https://" + lab.AllowedHost + "/home")
	require.NoError(t, err)

	return base + "/track/click2/" + blob + ".html"
}

func upnProbe(t *testing.T, base string) string {
	t.Helper()

	blob, err := lab.EncodeUPN("https://" + lab.AllowedHost + "/home")
	require.NoError(t, err)

	return base + "/ls/click?upn=" + blob
}

func jwtProbe(t *testing.T, base string) string {
	t.Helper()

	token, err := lab.EncodeJWT("https://" + lab.AllowedHost + "/home")
	require.NoError(t, err)

	return base + "/b03?token=" + token
}
