package adapter_test

import (
	"testing"

	"github.com/nedlir/detour/internal/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseBurpXML(t *testing.T) {
	t.Parallel()

	raw := `<?xml version="1.0"?>
<items burpVersion="2024.1">
  <item>
    <url><![CDATA[https://shop.example/logout?return=https://shop.example/]]></url>
  </item>
  <item>
    <url>file:///etc/passwd</url>
  </item>
</items>`

	got, err := adapter.ParseBurp([]byte(raw))
	require.NoError(t, err)
	assert.Equal(t, []string{"https://shop.example/logout?return=https://shop.example/"}, got)
}

func TestParseBurpJSON(t *testing.T) {
	t.Parallel()

	raw := `{"items":[{"url":"http://a.example/x"},{"url":"http://a.example/x"}]}`
	got, err := adapter.ParseBurp([]byte(raw))
	require.NoError(t, err)
	assert.Equal(t, []string{"http://a.example/x"}, got)
}

func TestParseBurpInvalid(t *testing.T) {
	t.Parallel()

	_, err := adapter.ParseBurp([]byte("<not-items>"))
	require.Error(t, err)
}

func FuzzParseBurp(f *testing.F) {
	fuzzHTTPURLs(f, adapter.ParseBurp,
		[]byte(`<items><item><url>https://a.example/</url></item></items>`),
		[]byte(`{"items":[{"url":"https://a.example/"}]}`),
		[]byte(`<!DOCTYPE items [<!ENTITY x "https://a.example/">]><items><item><url>&x;</url></item></items>`),
		[]byte(`{}`),
	)
}
