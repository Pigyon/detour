package decode_test

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/nedlir/detour/internal/decode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	layerB64URL    = "base64:url"
	layerB64URLRaw = "base64:url_raw"
	layerJSON      = "json"
)

// payloadJSON is chosen so its base64 needs padding and its standard and
// url-safe alphabets differ, which is what lets a variant assertion mean
// something.
const payloadJSON = `{"dest":"https://example.com/ü","id":7}`

func TestDecodeTransportLayers(t *testing.T) {
	t.Parallel()

	std := base64.StdEncoding.EncodeToString([]byte(payloadJSON))
	require.True(t, strings.ContainsAny(std, "+/"), "payload must distinguish the base64 alphabets")
	require.True(t, strings.HasSuffix(std, "="), "payload must distinguish padded from raw")

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "base64url padded",
			input: base64.URLEncoding.EncodeToString([]byte(payloadJSON)),
			want:  []string{layerB64URL, layerJSON},
		},
		{
			name:  "base64url raw",
			input: base64.RawURLEncoding.EncodeToString([]byte(payloadJSON)),
			want:  []string{layerB64URLRaw, layerJSON},
		},
		{
			name:  "base64 std",
			input: base64.StdEncoding.EncodeToString([]byte(payloadJSON)),
			want:  []string{"base64:std", layerJSON},
		},
		{
			name:  "base32",
			input: base32.StdEncoding.EncodeToString([]byte(payloadJSON)),
			want:  []string{"base32:std", layerJSON},
		},
		{
			name:  "hex lower",
			input: hex.EncodeToString([]byte(payloadJSON)),
			want:  []string{"hex:lower", layerJSON},
		},
		{
			name:  "hex upper",
			input: strings.ToUpper(hex.EncodeToString([]byte(payloadJSON))),
			want:  []string{"hex:upper", layerJSON},
		},
		{
			name:  "base64 std raw",
			input: base64.RawStdEncoding.EncodeToString([]byte(payloadJSON)),
			want:  []string{"base64:std_raw", layerJSON},
		},
		{
			name:  "no transport at all",
			input: payloadJSON,
			want:  []string{layerJSON},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			chain, err := decode.Decode(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, layerNamesOf(chain))

			// A transport layer must rebuild the token byte for byte.
			rebuilt, err := chain.Encode(chain.Value)
			require.NoError(t, err)
			assert.Equal(t, tt.input, rebuilt)
		})
	}
}

func TestDecodeCompressionLayers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		compress func([]byte) []byte
		want     []string
	}{
		{name: "zlib", compress: zlibBytes, want: []string{layerB64URL, "zlib", layerJSON}},
		{name: "gzip", compress: gzipBytes, want: []string{layerB64URL, "gzip", layerJSON}},
		{name: "brotli", compress: brotliBytes, want: []string{layerB64URL, "brotli", layerJSON}},
		{name: "deflate", compress: deflateBytes, want: []string{layerB64URL, "deflate", layerJSON}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			token := base64.URLEncoding.EncodeToString(tt.compress([]byte(payloadJSON)))

			chain, err := decode.Decode(token)
			require.NoError(t, err)
			assert.Equal(t, tt.want, layerNamesOf(chain))

			// Compression is not canonical, so the rebuilt token is checked by
			// decoding it again rather than by comparing bytes.
			rebuilt, err := chain.Encode(chain.Value)
			require.NoError(t, err)

			again, err := decode.Decode(rebuilt)
			require.NoError(t, err)
			assert.Equal(t, chain.Value, again.Value)
		})
	}
}

func TestDecodeStructuralLayers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "json object",
			input: base64.RawURLEncoding.EncodeToString([]byte(`{"next":"https://example.com/"}`)),
			want:  []string{layerB64URLRaw, layerJSON},
		},
		{
			name:  "json array",
			input: base64.RawURLEncoding.EncodeToString([]byte(`[1,"https://example.com/",true]`)),
			want:  []string{layerB64URLRaw, layerJSON},
		},
		{
			name:  "form body",
			input: base64.RawURLEncoding.EncodeToString([]byte("id=9&next=https%3A%2F%2Fexample.com%2F")),
			want:  []string{layerB64URLRaw, "form"},
		},
		{
			name:  "bare encoded destination",
			input: base64.RawURLEncoding.EncodeToString([]byte("https://example.com/welcome/page")),
			want:  []string{layerB64URLRaw, "text"},
		},
		{
			name:  "jwt claim",
			input: jwtToken(t, `{"redirect":"https://example.com/"}`),
			want:  []string{"jwt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			chain, err := decode.Decode(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, layerNamesOf(chain))
			assert.NotEmpty(t, decode.URLFields(chain.Value))
		})
	}
}

func TestDecodeJWTKeepsSignature(t *testing.T) {
	t.Parallel()

	token := jwtToken(t, `{"redirect":"https://example.com/"}`)

	chain, err := decode.Decode(token)
	require.NoError(t, err)

	rebuilt, err := chain.Encode(chain.Value)
	require.NoError(t, err)

	parts := strings.Split(rebuilt, ".")
	require.Len(t, parts, 3)
	assert.Equal(t, strings.Split(token, ".")[0], parts[0], "header carried verbatim")
	assert.Equal(t, strings.Split(token, ".")[2], parts[2], "signature carried verbatim")
}

func TestDecodeRejectsUnstructured(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "plain word", input: "welcome-to-the-dashboard"},
		{name: "bare number", input: base64.RawURLEncoding.EncodeToString([]byte("123456789012"))},
		{name: "json with no destination", input: base64.RawURLEncoding.EncodeToString([]byte(`{"id":7,"okay":true}`))},
		{name: "relative path only", input: base64.RawURLEncoding.EncodeToString([]byte("/account/settings"))},
		{name: "hmac blob", input: "aHR0cHM6Ly9hbGxvd2VkLmxhYi9ob21l.7f1c2d"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := decode.Decode(tt.input)
			require.ErrorIs(t, err, decode.ErrNotStructured)
		})
	}
}

func TestEnvelopeAcceptsStructureWithoutDestination(t *testing.T) {
	t.Parallel()

	token := base64.RawURLEncoding.EncodeToString([]byte(`{"id":7,"okay":true}`))

	_, err := decode.Decode(token)
	require.ErrorIs(t, err, decode.ErrNotStructured)

	chain, err := decode.Envelope(token)
	require.NoError(t, err)
	assert.Equal(t, []string{layerB64URLRaw, layerJSON}, layerNamesOf(chain))
}

func TestChainTechniqueID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "compressed wrapper is the kucoin class",
			input: base64.URLEncoding.EncodeToString(zlibBytes([]byte(payloadJSON))),
			want:  "OR-B01",
		},
		{
			name:  "plain wrapper is the esp class",
			input: base64.URLEncoding.EncodeToString([]byte(payloadJSON)),
			want:  "OR-B02",
		},
		{
			name:  "jwt claim",
			input: jwtToken(t, `{"redirect":"https://example.com/"}`),
			want:  "OR-B03",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			chain, err := decode.Decode(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, chain.TechniqueID())
		})
	}
}

// FuzzDecodeRoundTrip asserts the decoder's central promise: whatever chain it
// reports, re-encoding the decoded value must produce a token that decodes to
// the same value. A chain that cannot do that is not reversible, and a
// mutation replayed through it would not be the same envelope.
func FuzzDecodeRoundTrip(f *testing.F) {
	f.Add(base64.URLEncoding.EncodeToString([]byte(payloadJSON)))
	f.Add(base64.URLEncoding.EncodeToString(zlibBytes([]byte(payloadJSON))))
	f.Add(base64.RawURLEncoding.EncodeToString([]byte("https://example.com/x")))
	f.Add(hex.EncodeToString([]byte(payloadJSON)))
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJyZWRpcmVjdCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vIn0.sig")
	f.Add("")
	f.Add(strings.Repeat("A", 4096))

	f.Fuzz(func(t *testing.T, token string) {
		chain, err := decode.Envelope(token)
		if err != nil {
			return
		}

		require.NotEmpty(t, chain.Layers)

		rebuilt, err := chain.Encode(chain.Value)
		if err != nil {
			return
		}

		again, err := decode.Envelope(rebuilt)
		require.NoError(t, err, "a rebuilt token must decode again")
		assert.Equal(t, chain.Value, again.Value)
	})
}

func layerNamesOf(chain *decode.Chain) []string {
	out := make([]string, 0, len(chain.Layers))
	for _, l := range chain.Layers {
		out = append(out, l.Name())
	}

	return out
}

func jwtToken(t *testing.T, claims string) string {
	t.Helper()

	enc := base64.RawURLEncoding

	return enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		enc.EncodeToString([]byte(claims)) + ".c2lnbmF0dXJl"
}

func zlibBytes(raw []byte) []byte {
	var buf bytes.Buffer

	zw := zlib.NewWriter(&buf)
	_, _ = zw.Write(raw)
	_ = zw.Close()

	return buf.Bytes()
}

func gzipBytes(raw []byte) []byte {
	var buf bytes.Buffer

	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(raw)
	_ = zw.Close()

	return buf.Bytes()
}

func deflateBytes(raw []byte) []byte {
	var buf bytes.Buffer

	fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = fw.Write(raw)
	_ = fw.Close()

	return buf.Bytes()
}

func brotliBytes(raw []byte) []byte {
	var buf bytes.Buffer

	bw := brotli.NewWriter(&buf)
	_, _ = bw.Write(raw)
	_ = bw.Close()

	return buf.Bytes()
}
