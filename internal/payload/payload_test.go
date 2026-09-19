package payload_test

import (
	"testing"

	"github.com/nedlir/detour/internal/payload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		tmpl   string
		canary string
		target string
		want   string
	}{
		{
			name:   "userinfo",
			tmpl:   "https://{{target}}@{{canary}}",
			canary: "canary.invalid",
			target: "allowed.lab",
			want:   "https://allowed.lab@canary.invalid",
		},
		{
			name:   "protocol relative",
			tmpl:   "//{{canary}}",
			canary: "canary.invalid",
			target: "t.example",
			want:   "//canary.invalid",
		},
		{
			name:   "no tokens",
			tmpl:   "/safe",
			canary: "c",
			target: "t",
			want:   "/safe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := payload.Expand(payload.Payload{Template: tt.tmpl}, tt.canary, tt.target)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSubstituteKeyword(t *testing.T) {
	t.Parallel()

	raw := "https://app.example/go?next=FUZZ"
	got := payload.Substitute(raw, payload.DefaultKeyword, "https://canary.invalid")
	assert.Equal(t, "https://app.example/go?next=https://canary.invalid", got)
	assert.True(t, payload.HasKeyword(raw, payload.DefaultKeyword))
	assert.False(t, payload.HasKeyword(raw, ""))
	assert.Equal(t, raw, payload.Substitute(raw, "", "x"))
}

func TestBuiltInExpands(t *testing.T) {
	t.Parallel()

	set := payload.BuiltIn()
	require.NotEmpty(t, set)

	seen := map[string]struct{}{}

	for _, p := range set {
		require.NotEmpty(t, p.Technique)
		require.NotEmpty(t, p.Template)
		require.NotEmpty(t, p.Mechanism)

		got := payload.Expand(p, "canary.invalid", "allowed.lab")
		assert.NotContains(t, got, "{{canary}}")
		assert.NotContains(t, got, "{{target}}")
		assert.NotEmpty(t, got)

		seen[p.Technique] = struct{}{}
	}

	assert.Contains(t, seen, "OR-A01")
	assert.Contains(t, seen, "OR-A03")
	assert.Contains(t, seen, "OR-A11")
	assert.Contains(t, seen, "OR-D01")
}

func FuzzSubstitute(f *testing.F) {
	f.Add("https://x/FUZZ", "FUZZ", "https://c")
	f.Add("", "FUZZ", "a")
	f.Add("nope", "", "a")

	f.Fuzz(func(_ *testing.T, raw, keyword, value string) {
		_ = payload.Substitute(raw, keyword, value)
		_ = payload.HasKeyword(raw, keyword)
	})
}

func FuzzExpand(f *testing.F) {
	f.Add("https://{{target}}@{{canary}}", "c.invalid", "t.example")
	f.Add("{{canary}}{{canary}}", "c", "t")

	f.Fuzz(func(_ *testing.T, tmpl, canary, target string) {
		_ = payload.Expand(payload.Payload{Template: tmpl}, canary, target)
	})
}
