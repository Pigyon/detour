package confirm_test

import (
	"testing"

	"github.com/nedlir/detour/internal/confirm"
	"github.com/nedlir/detour/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProbeFor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		build    func() model.Finding
		want     string
		wantable bool
	}{
		{
			name: "a concrete probe is replayed as written",
			build: func() model.Finding {
				f := candidate("OR-A07", "https://site.lab/go", "url", "//x")
				f.ProbeURL = "https://site.lab/go?url=%2F%2Fcanary.invalid"

				return f
			},
			want:     "https://site.lab/go?url=%2F%2Fcanary.invalid",
			wantable: true,
		},
		{
			name: "a parameter payload is expanded and set",
			build: func() model.Finding {
				return candidate("OR-C01", "https://site.lab/signin", "backUrl", "https://{{canary}}/x")
			},
			want:     "https://site.lab/signin?backUrl=https%3A%2F%2Fcanary.invalid%2Fx",
			wantable: true,
		},
		{
			name: "a hash sink payload rides in the fragment",
			build: func() model.Finding {
				return candidate("OR-C02", "https://site.lab/page", "", "https://{{canary}}/x")
			},
			want:     "https://site.lab/page#https://canary.invalid/x",
			wantable: true,
		},
		{
			name: "the target placeholder becomes the source host",
			build: func() model.Finding {
				return candidate("OR-A01", "https://site.lab/go", "url", "https://{{target}}@{{canary}}/")
			},
			want:     "https://site.lab/go?url=https%3A%2F%2Fsite.lab%40canary.invalid%2F",
			wantable: true,
		},
		{
			name: "the allowed placeholder becomes a trusted host",
			build: func() model.Finding {
				f := candidate("OR-A13", "https://site.lab/go", "url", "https://{{canary}}.{{allowed}}/")
				f.Candidate.Validator = &model.Validator{Allowlist: []string{"https://allowed.lab/x"}}

				return f
			},
			want:     "https://site.lab/go?url=https%3A%2F%2Fcanary.invalid.allowed.lab%2F",
			wantable: true,
		},
		{
			name:     "reverse tabnabbing is not a navigation",
			build:    func() model.Finding { return candidate("OR-F09", "https://site.lab/p", "", "x") },
			wantable: false,
		},
		{
			name:     "a sandboxless frame is not a navigation",
			build:    func() model.Finding { return candidate("OR-C03", "https://site.lab/p", "", "x") },
			wantable: false,
		},
		{
			name:     "no parameter and no payload is not probeable",
			build:    func() model.Finding { return candidate("OR-C01", "https://site.lab/p", "", "") },
			wantable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := confirm.ProbeFor(tt.build(), "canary.invalid")
			require.Equal(t, tt.wantable, ok)

			if tt.wantable {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestFindChromeHonorsOverride(t *testing.T) {
	t.Setenv("DETOUR_CHROME", "/nonexistent/chrome")

	_, err := confirm.FindChrome()
	require.ErrorIs(t, err, confirm.ErrChromeNotFound)
	assert.False(t, confirm.Available())
}
