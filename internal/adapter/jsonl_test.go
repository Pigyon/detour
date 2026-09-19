package adapter_test

import (
	"testing"

	"github.com/nedlir/detour/internal/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseJSONL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "katana url",
			in:   `{"url":"https://a.example/login?next=/home"}` + "\n",
			want: []string{"https://a.example/login?next=/home"},
		},
		{
			name: "katana endpoint",
			in:   `{"request":{"endpoint":"https://b.example/"}}` + "\n",
			want: []string{"https://b.example/"},
		},
		{
			name: "httpx input",
			in:   `{"input":"https://c.example/"}` + "\n# skip\n",
			want: []string{"https://c.example/"},
		},
		{
			name: "skips junk lines",
			in:   "not json\n{\"url\":\"https://d.example/\"}\n",
			want: []string{"https://d.example/"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := adapter.ParseJSONL([]byte(tt.in))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func FuzzParseJSONL(f *testing.F) {
	f.Add([]byte("{\"url\":\"https://a.example/\"}\n"))
	f.Add([]byte("not json\n"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			t.Skip()
		}

		_, _ = adapter.ParseJSONL(data)
	})
}
