package adapter_test

import (
	"strings"
	"testing"

	"github.com/nedlir/detour/internal/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "skips blanks and comments",
			in:   "# c\n\nhttps://a.example/x\n  https://b.example/y  \n",
			want: []string{"https://a.example/x", "https://b.example/y"},
		},
		{name: "empty", in: "\n# only\n", want: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := adapter.Load(strings.NewReader(tt.in))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func FuzzLoad(f *testing.F) {
	f.Add("# hi\nhttps://x.example/\n")
	f.Add("")
	f.Add("   \n#\n")

	f.Fuzz(func(t *testing.T, in string) {
		got, err := adapter.Load(strings.NewReader(in))
		if err != nil {
			return
		}

		for _, u := range got {
			require.NotEmpty(t, u)
			require.NotEqual(t, '#', u[0])
		}
	})
}
