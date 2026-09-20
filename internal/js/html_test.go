package js_test

import (
	"testing"

	"github.com/nedlir/detour/internal/js"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHTMLVerdicts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		body   string
		wantID string
	}{
		{
			name:   "external blank target without noopener",
			body:   `<a href="https://other.example/" target="_blank">x</a>`,
			wantID: "OR-F09",
		},
		{
			name:   "iframe without sandbox",
			body:   `<iframe src="/frame"></iframe>`,
			wantID: "OR-C03",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc, err := js.ParseHTML("https://site.lab/page", []byte(tt.body))
			require.NoError(t, err)
			require.Len(t, doc.Verdicts, 1)
			assert.Equal(t, tt.wantID, doc.Verdicts[0].TechniqueID)
			assert.NotEmpty(t, doc.Verdicts[0].Discrepancy)
		})
	}
}

func TestParseHTMLQuietCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{name: "noopener present", body: `<a href="https://other.example/" target="_blank" rel="noopener">x</a>`},
		{name: "noreferrer also counts", body: `<a href="https://other.example/" target="_blank" rel="noreferrer">x</a>`},
		{name: "same host link", body: `<a href="https://site.lab/other" target="_blank">x</a>`},
		{name: "relative link", body: `<a href="/other" target="_blank">x</a>`},
		{name: "no blank target", body: `<a href="https://other.example/">x</a>`},
		{name: "sandboxed iframe", body: `<iframe src="/frame" sandbox></iframe>`},
		{name: "srcless iframe", body: `<iframe></iframe>`},
		{name: "empty", body: ``},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc, err := js.ParseHTML("https://site.lab/page", []byte(tt.body))
			require.NoError(t, err)
			assert.Empty(t, doc.Verdicts)
		})
	}
}

func TestParseHTMLScripts(t *testing.T) {
	t.Parallel()

	body := `<script src="/static/app.js"></script>
<script src="https://cdn.example/lib.js"></script>
<script>location.href = u</script>
<script>   </script>`

	doc, err := js.ParseHTML("https://site.lab/page", []byte(body))
	require.NoError(t, err)
	require.Len(t, doc.Scripts, 3, "the whitespace-only script is skipped")

	assert.Equal(t, "https://site.lab/static/app.js", doc.Scripts[0].Src, "relative src resolves against the page")
	assert.Equal(t, "https://cdn.example/lib.js", doc.Scripts[1].Src)
	assert.Empty(t, doc.Scripts[2].Src)
	assert.Contains(t, string(doc.Scripts[2].Body), "location.href")
}

func FuzzParseHTML(f *testing.F) {
	f.Add(`<a href="https://x/" target="_blank">x</a>`)
	f.Add(`<script src="/a.js"></script>`)
	f.Add(`<iframe src=x>`)
	f.Add(``)
	f.Add(`<<<<>>>>`)

	f.Fuzz(func(t *testing.T, body string) {
		doc, err := js.ParseHTML("https://site.lab/p", []byte(body))
		if err != nil {
			return
		}

		for _, v := range doc.Verdicts {
			assert.NotEmpty(t, v.TechniqueID)
			assert.NotEmpty(t, v.Severity)
		}
	})
}
