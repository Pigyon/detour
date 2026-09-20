package confirm_test

import (
	"context"
	"testing"

	"github.com/nedlir/detour/internal/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRefererTest is the automated form of the manual check: host a page,
// click a link, watch where the browser ends up. It is the only way to settle
// an endpoint whose input is the Referer the browser sends by itself.
func TestRefererTest(t *testing.T) {
	t.Parallel()
	requireChrome(t)

	srv := labServer(t)
	c := newConfirmer(t, scope.New(testCanary))

	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "referer used as the destination", path: "/d05", want: true},
		{name: "static redirect does not follow the referer", path: "/decoy/static", want: false},
		{name: "reflection only", path: "/decoy/reflect?url=x", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := c.RefererTest(context.Background(), srv.URL+tt.path)
			require.NoError(t, err)
			assert.Equal(t, tt.want, result.Returned)
			assert.Equal(t, tt.want, result.Confirmed)
			assert.Contains(t, result.LinkPage, "127.0.0.1")
		})
	}
}
