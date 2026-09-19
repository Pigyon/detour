package decode_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/nedlir/detour/internal/decode"
	"github.com/nedlir/detour/internal/lab"
	"github.com/nedlir/detour/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const clickPrefix = "https://trace.lab/track/click2/"

func TestFindLocatesBlobs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		source     string
		wantCount  int
		wantRep    model.Representation
		wantParam  string
		wantSuffix string
		wantLayers []string
	}{
		{
			name:       "compressed click wrapper in a path segment",
			source:     clickPrefix + clickBlob(t, "https://example.com/welcome") + ".html",
			wantCount:  1,
			wantRep:    model.RepresentationPathSegment,
			wantSuffix: ".html",
			wantLayers: []string{layerB64URL, "zlib", layerJSON},
		},
		{
			name:       "unsigned wrapper in a query value",
			source:     "https://esp.lab/ls/click?upn=" + upnBlob(t, "https://example.com/welcome"),
			wantCount:  1,
			wantRep:    model.RepresentationQueryParameter,
			wantParam:  "upn",
			wantLayers: []string{layerB64URL, layerJSON},
		},
		{
			name:       "jwt in a query value",
			source:     "https://sso.lab/go?token=" + jwtBlob(t, "https://example.com/welcome"),
			wantCount:  1,
			wantRep:    model.RepresentationQueryParameter,
			wantParam:  "token",
			wantLayers: []string{"jwt"},
		},
		{
			name:      "a plain parameter is not a blob",
			source:    "https://site.lab/go?url=https://example.com/welcome",
			wantCount: 0,
		},
		{
			name:      "a signed envelope that does not decode is not a blob",
			source:    "https://site.lab/s/" + lab.SignDest("https://example.com/welcome"),
			wantCount: 0,
		},
		{
			name:      "no blob anywhere",
			source:    "https://site.lab/account/settings?page=2",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			blobs, err := decode.Find(tt.source)
			require.NoError(t, err)
			require.Len(t, blobs, tt.wantCount)

			if tt.wantCount == 0 {
				return
			}

			got := blobs[0]
			assert.Equal(t, tt.wantRep, got.Site.Representation)
			assert.Equal(t, tt.wantParam, got.Site.ParamName)
			assert.Equal(t, tt.wantSuffix, got.Site.Suffix)
			assert.Equal(t, tt.wantLayers, layerNamesOf(got.Chain))
			require.NotEmpty(t, got.Fields)
			assert.Equal(t, "https://example.com/welcome", got.Fields[0].Value)
		})
	}
}

// TestReplaceKucoinEnvelope is the golden fixture for the class detour was
// built for: the destination is field 4 of a 17-element array inside
// base64url(zlib(json)), wearing a .html suffix. Only that field may move.
func TestReplaceKucoinEnvelope(t *testing.T) {
	t.Parallel()

	original := "https://example.com/welcome"
	source := clickPrefix + clickBlob(t, original) + ".html"

	blobs, err := decode.Find(source)
	require.Len(t, blobs, 1)
	require.NoError(t, err)

	blob := blobs[0]
	require.Len(t, blob.Fields, 1)

	field := blob.Fields[0]
	assert.Equal(t, model.FieldPath("$[4]"), field.Path)
	assert.Equal(t, original, field.Value)
	assert.True(t, field.Escaped, "the envelope stores the destination percent-encoded")

	mutated, err := blob.Replace(source, field, "https://canary.invalid/x")
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(mutated, ".html"), "the cosmetic suffix is put back")

	// The server's own decoder must accept the rebuilt envelope, with every
	// field except the destination untouched.
	before := decodeClick(t, source)

	after := decodeClick(t, mutated)
	assert.Equal(t, "https://canary.invalid/x", after.Dest)
	assert.Equal(t, before.Host, after.Host)
	assert.Equal(t, before.Campaign, after.Campaign)
	assert.Equal(t, before.Integrity, after.Integrity)
}

func TestSiteApply(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		site decode.Site
		base string
		want string
	}{
		{
			name: "query parameter",
			site: decode.Site{Representation: model.RepresentationQueryParameter, ParamName: "upn"},
			base: "https://esp.lab/ls/click?upn=old&mid=9",
			want: "https://esp.lab/ls/click?mid=9&upn=TOKEN",
		},
		{
			name: "path segment with a suffix",
			site: decode.Site{Representation: model.RepresentationPathSegment, SegmentIndex: 3, Suffix: ".html"},
			base: "https://trace.lab/track/click2/old.html",
			want: "https://trace.lab/track/click2/TOKEN",
		},
		{
			name: "segment out of range",
			site: decode.Site{Representation: model.RepresentationPathSegment, SegmentIndex: 9},
			base: "https://trace.lab/a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := tt.site.Apply(tt.base, "TOKEN")
			if tt.want == "" {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCandidates(t *testing.T) {
	t.Parallel()

	source := "https://esp.lab/ls/click?upn=" + upnBlob(t, "https://example.com/welcome")

	cands, err := decode.Candidates(source)
	require.NoError(t, err)
	require.Len(t, cands, 1)

	cand := cands[0]
	assert.Equal(t, model.RepresentationOpaqueBlob, cand.Representation)
	assert.Equal(t, "upn", cand.ParamName)
	assert.Equal(t, []model.Decoder{{Kind: layerB64URL}, {Kind: layerJSON}}, cand.DecoderChain)
	assert.Equal(t, []model.FieldPath{"$.url"}, cand.URLFields)
}

func TestFindRejectsBadSource(t *testing.T) {
	t.Parallel()

	_, err := decode.Find("https://exa mple.com/\x7f")
	require.Error(t, err)
}

// FuzzFind asserts the decoder never panics on a hostile URL and that every
// blob it reports can be mutated and rebuilt into a parseable URL.
func FuzzFind(f *testing.F) {
	f.Add(clickPrefix + "eJxLyU9OLcpMzFEoLsnMS1cA.html")
	f.Add("https://esp.lab/ls/click?upn=eyJ1cmwiOiJodHRwczovL2EuYi8ifQ")
	f.Add("https://a/b?x=y")
	f.Add("")
	f.Add("://")

	f.Fuzz(func(t *testing.T, raw string) {
		blobs, err := decode.Find(raw)
		if err != nil {
			return
		}

		for _, b := range blobs {
			require.NotEmpty(t, b.Fields, "Find only reports blobs holding a destination")

			for _, field := range b.Fields {
				mutated, err := b.Replace(raw, field, "https://canary.invalid/")
				if err != nil {
					continue
				}

				_, err = url.Parse(mutated)
				require.NoError(t, err, "a rebuilt envelope must still be a URL")
			}
		}
	})
}

func clickBlob(t *testing.T, dest string) string {
	t.Helper()

	blob, err := lab.EncodeClick(dest)
	require.NoError(t, err)

	return blob
}

func upnBlob(t *testing.T, dest string) string {
	t.Helper()

	blob, err := lab.EncodeUPN(dest)
	require.NoError(t, err)

	return blob
}

func jwtBlob(t *testing.T, dest string) string {
	t.Helper()

	token, err := lab.EncodeJWT(dest)
	require.NoError(t, err)

	return token
}

func decodeClick(t *testing.T, source string) lab.ClickEnvelope {
	t.Helper()

	parsed, err := url.Parse(source)
	require.NoError(t, err)

	segments := strings.Split(parsed.EscapedPath(), "/")

	token, err := url.PathUnescape(segments[len(segments)-1])
	require.NoError(t, err)

	env, err := lab.DecodeClick(token)
	require.NoError(t, err)

	return env
}

func stringReader(s string) *strings.Reader {
	return strings.NewReader(s)
}
