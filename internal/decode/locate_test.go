package decode_test

import (
	"encoding/json"
	"testing"

	"github.com/nedlir/detour/internal/decode"
	"github.com/nedlir/detour/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURLFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		raw       string
		wantPaths []model.FieldPath
		wantValue string
		wantEsc   bool
	}{
		{
			name:      "top level key",
			raw:       `{"url":"https://example.com/a"}`,
			wantPaths: []model.FieldPath{"$.url"},
			wantValue: "https://example.com/a",
		},
		{
			name:      "array element",
			raw:       `[0,"x","https://example.com/a"]`,
			wantPaths: []model.FieldPath{"$[2]"},
			wantValue: "https://example.com/a",
		},
		{
			name:      "nested at depth",
			raw:       `{"a":{"b":[{"c":"https://example.com/deep"}]}}`,
			wantPaths: []model.FieldPath{"$.a.b[0].c"},
			wantValue: "https://example.com/deep",
		},
		{
			name:      "percent encoded value",
			raw:       `{"d":"https%3A%2F%2Fexample.com%2Fenc"}`,
			wantPaths: []model.FieldPath{"$.d"},
			wantValue: "https://example.com/enc",
			wantEsc:   true,
		},
		{
			name:      "protocol relative",
			raw:       `{"d":"//example.com/pr"}`,
			wantPaths: []model.FieldPath{"$.d"},
			wantValue: "//example.com/pr",
		},
		{
			name:      "key needing quoting",
			raw:       `{"next url":"https://example.com/q"}`,
			wantPaths: []model.FieldPath{`$["next url"]`},
			wantValue: "https://example.com/q",
		},
		{
			name:      "no destination",
			raw:       `{"id":7,"path":"/account","host":"example.com"}`,
			wantPaths: []model.FieldPath{},
		},
		{
			name:      "several destinations stay sorted",
			raw:       `{"b":"https://example.com/b","a":"https://example.com/a"}`,
			wantPaths: []model.FieldPath{"$.a", "$.b"},
			wantValue: "https://example.com/a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fields := decode.URLFields(unmarshal(t, tt.raw))

			paths := make([]model.FieldPath, 0, len(fields))
			for _, f := range fields {
				paths = append(paths, f.Path)
			}

			assert.Equal(t, tt.wantPaths, paths)

			if tt.wantValue != "" {
				require.NotEmpty(t, fields)
				assert.Equal(t, tt.wantValue, fields[0].Value)
				assert.Equal(t, tt.wantEsc, fields[0].Escaped)
			}
		})
	}
}

func unmarshal(t *testing.T, raw string) any {
	t.Helper()

	var value any

	dec := json.NewDecoder(stringReader(raw))
	dec.UseNumber()
	require.NoError(t, dec.Decode(&value))

	return value
}
