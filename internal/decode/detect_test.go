package decode_test

import (
	"testing"

	"github.com/nedlir/detour/internal/decode"
	"github.com/stretchr/testify/assert"
)

// sampleBlob is a short base64url token used across the detection cases.
const sampleBlob = "eJxLyU9OLcpMzFEoLsnMS1cA"

func TestStripSuffix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		wantBody   string
		wantSuffix string
	}{
		{
			name:       "html suffix on a blob",
			input:      sampleBlob + ".html",
			wantBody:   sampleBlob,
			wantSuffix: ".html",
		},
		{
			name:       "uppercase suffix",
			input:      sampleBlob + ".HTML",
			wantBody:   sampleBlob,
			wantSuffix: ".HTML",
		},
		{
			name:     "no suffix",
			input:    sampleBlob,
			wantBody: sampleBlob,
		},
		{
			name:     "unknown extension is part of the token",
			input:    sampleBlob + ".deadbeef",
			wantBody: sampleBlob + ".deadbeef",
		},
		{
			name:     "empty",
			input:    "",
			wantBody: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			token, suffix := decode.StripSuffix(tt.input)
			assert.Equal(t, tt.wantBody, token)
			assert.Equal(t, tt.wantSuffix, suffix)
		})
	}
}

func TestIsOpaque(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "base64url blob", input: "eJxLyU9OLcpMzFEoLsnMS1cAAFnnBJk", want: true},
		{name: "hex digest", input: "5d41402abc4b2a76b9719d911017c592", want: true},
		{name: "jwt", input: "eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.sig", want: true},
		{name: "too short", input: "eJxLyU9OLc", want: false},
		{name: "english word run", input: "aaaaaaaaaaaaaaaaaaaaaaaaaaa", want: false},
		{name: "a url is not opaque", input: "https://example.com/path/here", want: false},
		{name: "empty", input: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, decode.IsOpaque(tt.input))
		})
	}
}

func TestEntropy(t *testing.T) {
	t.Parallel()

	assert.InDelta(t, 0.0, decode.Entropy(""), 1e-9)
	assert.InDelta(t, 0.0, decode.Entropy("aaaa"), 1e-9)
	assert.InDelta(t, 1.0, decode.Entropy("abab"), 1e-9)
	assert.InDelta(t, 2.0, decode.Entropy("abcd"), 1e-9)
	assert.Greater(t, decode.Entropy("eJxLyU9OLcpMzFEoLsnMS1cAAFnnBJk"), 3.0)
}

func FuzzIsOpaque(f *testing.F) {
	f.Add(sampleBlob + ".html")
	f.Add("")
	f.Add("....")
	f.Add("\x00\x00\x00")

	f.Fuzz(func(t *testing.T, token string) {
		stripped, suffix := decode.StripSuffix(token)
		assert.Equal(t, token, stripped+suffix, "strip must be lossless")

		decode.IsOpaque(stripped)

		e := decode.Entropy(token)
		assert.GreaterOrEqual(t, e, 0.0)
		assert.LessOrEqual(t, e, 8.0)
	})
}
