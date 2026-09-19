package adapter_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func fuzzHTTPURLs(f *testing.F, parse func([]byte) ([]string, error), seeds ...[]byte) {
	f.Helper()

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			t.Skip()
		}

		urls, err := parse(data)
		if err != nil {
			return
		}

		for _, u := range urls {
			require.True(t, strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://"))
		}
	})
}
