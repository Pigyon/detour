package dork_test

import (
	"strings"
	"testing"

	"github.com/nedlir/detour/internal/dork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	t.Parallel()

	queries := dork.Generate("Example.COM")
	require.NotEmpty(t, queries)

	joined := strings.Join(texts(queries), "\n")

	assert.Contains(t, joined, "site:example.com inurl:redirect_uri=")
	assert.Contains(t, joined, `site:example.com inurl:"/track/click2/"`)
	assert.Contains(t, joined, `site:example.com inurl:"=http"`)
	assert.Contains(t, joined, "org:example")

	for _, q := range queries {
		assert.NotEmpty(t, q.Why, "every query explains what it looks for")
		assert.NotEmpty(t, q.Engine)
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	t.Parallel()

	first := texts(dork.Generate("a.lab"))
	second := texts(dork.Generate("a.lab"))

	assert.Equal(t, first, second)
}

func TestGenerateHandlesEdgeCases(t *testing.T) {
	t.Parallel()

	assert.Empty(t, dork.Generate(""))
	assert.Empty(t, dork.Generate("   "))
	assert.NotEmpty(t, dork.Generate("localhost"), "a single label still generates web queries")
}

// TestGenerateIsOffline pins the contract: generation never needs the network,
// so the whole set is produced from the domain string alone.
func TestGenerateIsOffline(t *testing.T) {
	t.Parallel()

	for _, q := range dork.Generate("a.lab") {
		assert.NotContains(t, q.Query, "http://")
		assert.NotContains(t, q.Query, "https://")
	}
}

func texts(queries []dork.Query) []string {
	out := make([]string, 0, len(queries))
	for _, q := range queries {
		out = append(out, q.Query)
	}

	return out
}
