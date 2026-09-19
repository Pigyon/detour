package adapter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nedlir/detour/internal/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		file string
		in   string
		want adapter.Format
	}{
		{name: "har extension", file: "run.har", in: "{}", want: adapter.FormatHAR},
		{name: "xml extension", file: "burp.xml", in: "<x/>", want: adapter.FormatBurp},
		{name: "jsonl extension", file: "out.jsonl", in: "https://a", want: adapter.FormatJSONL},
		{
			name: "har body",
			file: "run.txt",
			in:   `{"log":{"entries":[]}}`,
			want: adapter.FormatHAR,
		},
		{
			name: "burp xml body",
			file: "run.txt",
			in:   `<items><item><url>https://a.example/</url></item></items>`,
			want: adapter.FormatBurp,
		},
		{
			name: "url list",
			file: "urls.txt",
			in:   "https://a.example/\n",
			want: adapter.FormatURLList,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := adapter.Detect(tt.file, []byte(tt.in))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLoadBytesHAR(t *testing.T) {
	t.Parallel()

	raw := `{
	  "log": {
	    "entries": [
	      {"request": {"url": "https://a.example/login?next=https://a.example/"}},
	      {"request": {"url": "javascript:alert(1)"}},
	      {"request": {"url": "https://a.example/login?next=https://a.example/"}}
	    ]
	  }
	}`

	got, err := adapter.LoadBytes([]byte(raw), "session.har")
	require.NoError(t, err)
	assert.Equal(t, []string{"https://a.example/login?next=https://a.example/"}, got)
}

func TestLoadPathUsesExtension(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "run.har")
	raw := `{"log":{"entries":[{"request":{"url":"https://b.example/x"}}]}}`
	require.NoError(t, os.WriteFile(path, []byte(raw), 0o600))

	got, err := adapter.LoadPath(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://b.example/x"}, got)
}

func TestParseHARInvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := adapter.ParseHAR([]byte("{not json"))
	require.Error(t, err)
}

func FuzzParseHAR(f *testing.F) {
	fuzzHTTPURLs(f, adapter.ParseHAR,
		[]byte(`{"log":{"entries":[{"request":{"url":"https://a.example/"}}]}}`),
		[]byte(`{}`),
		[]byte(`{"log":{"entries":[]}}`),
		[]byte(`<items/>`),
	)
}
