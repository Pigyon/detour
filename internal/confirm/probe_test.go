package confirm_test

import (
	"testing"

	"github.com/nedlir/detour/internal/confirm"
	"github.com/nedlir/detour/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProbesFor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		build func() model.Finding
		want  []string
	}{
		{
			name: "a concrete probe is replayed as written",
			build: func() model.Finding {
				f := candidate("OR-A07", "https://site.lab/go", "url", "//x")
				f.ProbeURL = "https://site.lab/go?url=%2F%2Fcanary.invalid"

				return f
			},
			want: []string{"https://site.lab/go?url=%2F%2Fcanary.invalid"},
		},
		{
			name: "a parameter payload is expanded and set",
			build: func() model.Finding {
				return candidate("OR-C01", "https://site.lab/signin", "backUrl", "https://{{canary}}/x")
			},
			want: []string{"https://site.lab/signin?backUrl=https%3A%2F%2Fcanary.invalid%2Fx"},
		},
		{
			name: "a hash sink payload rides in the fragment",
			build: func() model.Finding {
				return candidate("OR-C02", "https://site.lab/page", "", "https://{{canary}}/x")
			},
			want: []string{"https://site.lab/page#https://canary.invalid/x"},
		},
		{
			name: "the target placeholder becomes the source host",
			build: func() model.Finding {
				return candidate("OR-A01", "https://site.lab/go", "url", "https://{{target}}@{{canary}}/")
			},
			want: []string{"https://site.lab/go?url=https%3A%2F%2Fsite.lab%40canary.invalid%2F"},
		},
		{
			name: "the allowed placeholder becomes a trusted host",
			build: func() model.Finding {
				f := candidate("OR-A13", "https://site.lab/go", "url", "https://{{canary}}.{{allowed}}/")
				f.Candidate.Validator = &model.Validator{Allowlist: []string{"https://allowed.lab/x"}}

				return f
			},
			want: []string{"https://site.lab/go?url=https%3A%2F%2Fcanary.invalid.allowed.lab%2F"},
		},
		{
			name:  "reverse tabnabbing is not a navigation",
			build: func() model.Finding { return candidate("OR-F09", "https://site.lab/p", "", "x") },
			want:  nil,
		},
		{
			name:  "a sandboxless frame is not a navigation",
			build: func() model.Finding { return candidate("OR-C03", "https://site.lab/p", "", "x") },
			want:  nil,
		},
		{
			name:  "no parameter and no payload is not probeable",
			build: func() model.Finding { return candidate("OR-C01", "https://site.lab/p", "", "") },
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := confirm.ProbesFor(tt.build(), "canary.invalid")

			if tt.want == nil {
				assert.Empty(t, got)

				return
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

// TestProbesForGuessingTriesExistingParamsFirst proves a parameter already
// on the URL is tried before the canonical list: the tracer found some
// evidence tying the sink to this page, which the canonical names carry no
// such evidence for.
func TestProbesForGuessingTriesExistingParamsFirst(t *testing.T) {
	t.Parallel()

	f := candidate("OR-C01", "https://site.lab/app?b=1&a=2", "", "https://{{canary}}/")
	got := confirm.ProbesFor(f, "canary.invalid")

	require.GreaterOrEqual(t, len(got), 2)
	assert.Equal(t, []string{
		"https://site.lab/app?a=https%3A%2F%2Fcanary.invalid%2F&b=1",
		"https://site.lab/app?a=2&b=https%3A%2F%2Fcanary.invalid%2F",
	}, got[:2])
}

// TestProbesForGuessingFallsBackToCanonicalNames proves an unresolved
// parameter is still probeable even with no query at all to guess from: the
// corpus's own canonical redirect-shaped names are the wider net, which is
// exactly what --deep's own brute force uses for the same situation on a
// harvested URL with no candidate.
func TestProbesForGuessingFallsBackToCanonicalNames(t *testing.T) {
	t.Parallel()

	f := candidate("OR-C01", "https://site.lab/app", "", "https://{{canary}}/")
	got := confirm.ProbesFor(f, "canary.invalid")

	require.NotEmpty(t, got, "canonical names must still give something to try")
	assert.Contains(t, got, "https://site.lab/app?url=https%3A%2F%2Fcanary.invalid%2F")
	assert.Contains(t, got, "https://site.lab/app?next=https%3A%2F%2Fcanary.invalid%2F")
}

// TestProbesForGuessingNeverRepeatsAParam proves the union of existing and
// canonical names is deduplicated: a parameter already on the URL that also
// happens to be one of the canonical names is tried once, not twice.
func TestProbesForGuessingNeverRepeatsAParam(t *testing.T) {
	t.Parallel()

	f := candidate("OR-C01", "https://site.lab/app?url=x", "", "https://{{canary}}/")
	got := confirm.ProbesFor(f, "canary.invalid")

	seen := map[string]int{}
	for _, probe := range got {
		seen[probe]++
	}

	for probe, count := range seen {
		assert.Equal(t, 1, count, "probe %q must not be attempted twice", probe)
	}
}

func TestFindChromeHonorsOverride(t *testing.T) {
	t.Setenv("DETOUR_CHROME", "/nonexistent/chrome")

	_, err := confirm.FindChrome()
	require.ErrorIs(t, err, confirm.ErrChromeNotFound)
	assert.False(t, confirm.Available())
}
