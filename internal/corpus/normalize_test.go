package corpus_test

import (
	"net/url"
	"testing"

	"github.com/nedlir/detour/internal/corpus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// urlGo is the plain endpoint most normalization cases reduce to.
const urlGo = "https://a.lab/go"

func TestNormalize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
		keep  bool
	}{
		{name: "already canonical", input: urlGoWithURL, want: urlGoWithURL, keep: true},
		{name: "scheme and host lowercased", input: "HTTPS://A.LAB/go", want: urlGo, keep: true},
		{name: "default https port dropped", input: "https://a.lab:443/go", want: urlGo, keep: true},
		{name: "default http port dropped", input: "http://a.lab:80/go", want: "http://a.lab/go", keep: true},
		{name: "explicit port kept", input: "https://a.lab:8443/go", want: "https://a.lab:8443/go", keep: true},
		{name: "fragment dropped", input: "https://a.lab/go#frag", want: urlGo, keep: true},
		//nolint:gosec // G101: a userinfo fixture is the point of this case.
		{name: "userinfo dropped", input: "https://u:p@a.lab/go", want: urlGo, keep: true},
		{name: "duplicate slashes collapsed", input: "https://a.lab//a///b", want: "https://a.lab/a/b", keep: true},
		{name: "dot segments resolved", input: "https://a.lab/a/../b", want: "https://a.lab/b", keep: true},
		{name: "trailing slash preserved", input: "https://a.lab/a/", want: "https://a.lab/a/", keep: true},
		{name: "empty path becomes root", input: "https://a.lab", want: "https://a.lab/", keep: true},
		{
			name:  "query sorted so order does not matter",
			input: "https://a.lab/go?b=2&a=1",
			want:  "https://a.lab/go?a=1&b=2",
			keep:  true,
		},
		{name: "css dropped", input: "https://a.lab/app.css", keep: false},
		{name: "image dropped", input: "https://a.lab/logo.PNG", keep: false},
		{name: "font dropped", input: "https://a.lab/f.woff2", keep: false},
		{name: "non http scheme dropped", input: "ftp://a.lab/x", keep: false},
		{name: "javascript scheme dropped", input: "javascript:alert(1)", keep: false},
		{name: "relative dropped", input: "/just/a/path", keep: false},
		{name: "empty dropped", input: "", keep: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := corpus.Normalize(tt.input)
			require.Equal(t, tt.keep, ok)

			if tt.keep {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

// TestShapeCollapsesIdentifiers is the reason selection works at all: an
// archive dump of a hundred thousand article URLs is one endpoint.
func TestShapeCollapsesIdentifiers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    string
		b    string
		same bool
	}{
		{name: "numeric ids", a: "https://a.lab/article/1", b: "https://a.lab/article/99999", same: true},
		{
			name: "uuids",
			a:    "https://a.lab/u/3f2504e0-4f89-11d3-9a0c-0305e82c3301",
			b:    "https://a.lab/u/6ba7b810-9dad-11d1-80b4-00c04fd430c8",
			same: true,
		},
		{
			name: "long opaque segments",
			a:    "https://a.lab/t/eJxLyU9OLcpMzFEoLsnMS1cA",
			b:    "https://a.lab/t/eJyrVkrLz1eyUsrJT84uLikCAB0TBHk",
			same: true,
		},
		{
			name: "same params different values",
			a:    "https://a.lab/go?url=one",
			b:    "https://a.lab/go?url=two",
			same: true,
		},
		{name: "different paths", a: "https://a.lab/one", b: "https://a.lab/two", same: false},
		{
			name: "different param sets",
			a:    urlGoWithURL,
			b:    "https://a.lab/go?next=x",
			same: false,
		},
		{name: "different hosts", a: urlGo, b: "https://b.lab/go", same: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sa, ok := corpus.Shape(tt.a)
			require.True(t, ok)

			sb, ok := corpus.Shape(tt.b)
			require.True(t, ok)

			assert.Equal(t, tt.same, sa == sb, "%s vs %s", sa, sb)
		})
	}
}

// FuzzNormalize asserts normalization never panics and always produces a
// parseable, canonical URL.
func FuzzNormalize(f *testing.F) {
	f.Add(urlGoWithURL)
	f.Add("HTTP://A.LAB:80//a/../b#frag")
	f.Add("")
	f.Add("://")
	f.Add("https://a.lab/\x00")

	f.Fuzz(func(t *testing.T, raw string) {
		got, ok := corpus.Normalize(raw)
		if !ok {
			return
		}

		parsed, err := url.Parse(got)
		require.NoError(t, err, "normalize must produce a parseable url")
		assert.NotEmpty(t, parsed.Host)
		assert.Empty(t, parsed.Fragment)
		assert.Nil(t, parsed.User)

		// Normalization has to be idempotent, or dedupe is unreliable.
		again, ok := corpus.Normalize(got)
		require.True(t, ok)
		assert.Equal(t, got, again)

		if _, ok := corpus.Shape(got); ok {
			_, _ = corpus.Classify(got)
		}
	})
}
