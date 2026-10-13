package client

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveBrowserProfileChrome(t *testing.T) {
	t.Parallel()

	p, err := resolveBrowserProfile("chrome")
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Contains(t, p.headers.Get("Accept"), "text/html")
	assert.Empty(t, p.headers.Get("User-Agent"), "User-Agent must not be baked in")
}

func TestResolveBrowserProfileFirefox(t *testing.T) {
	t.Parallel()

	p, err := resolveBrowserProfile("Firefox")
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "en-US,en;q=0.5", p.headers.Get("Accept-Language"))
	assert.Empty(t, p.headers.Get("User-Agent"), "User-Agent must not be baked in")
}

func TestResolveBrowserDefaultsImpersonateUsesProvidedUA(t *testing.T) {
	t.Parallel()

	p, err := resolveBrowserProfile("chrome")
	require.NoError(t, err)

	defaults, err := resolveBrowserDefaults(p, "my-real-ua/1.0", http.Header{})
	require.NoError(t, err)
	assert.Equal(t, "my-real-ua/1.0", defaults.Get("User-Agent"))
	assert.Contains(t, defaults.Get("Accept"), "text/html")
}

func TestResolveBrowserDefaultsImpersonateFallsBackToHeaderUA(t *testing.T) {
	t.Parallel()

	p, err := resolveBrowserProfile("chrome")
	require.NoError(t, err)

	inline := http.Header{"User-Agent": {"from-header/2.0"}}
	defaults, err := resolveBrowserDefaults(p, "", inline)
	require.NoError(t, err)
	assert.Equal(t, "from-header/2.0", defaults.Get("User-Agent"))
}

func TestResolveBrowserDefaultsImpersonateRequiresUA(t *testing.T) {
	t.Parallel()

	p, err := resolveBrowserProfile("chrome")
	require.NoError(t, err)

	_, err = resolveBrowserDefaults(p, "", http.Header{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "needs a User-Agent")
}

func TestResolveBrowserDefaultsNoImpersonateNoUAIsNil(t *testing.T) {
	t.Parallel()

	defaults, err := resolveBrowserDefaults(nil, "", http.Header{})
	require.NoError(t, err)
	assert.Nil(t, defaults)
}

func TestResolveBrowserDefaultsNoImpersonateWithUA(t *testing.T) {
	t.Parallel()

	defaults, err := resolveBrowserDefaults(nil, "cli-ua/3.0", http.Header{})
	require.NoError(t, err)
	assert.Equal(t, "cli-ua/3.0", defaults.Get("User-Agent"))
}

func TestResolveBrowserProfileEmpty(t *testing.T) {
	t.Parallel()

	p, err := resolveBrowserProfile("")
	require.NoError(t, err)
	assert.Nil(t, p)
}

func TestResolveBrowserProfileUnknown(t *testing.T) {
	t.Parallel()

	_, err := resolveBrowserProfile("netscape")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown --tls-impersonate")
}

func TestApplyBrowserDefaultsSetsUnsetHeaders(t *testing.T) {
	t.Parallel()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)

	defaults := http.Header{
		"User-Agent":      {"TestBrowser/1.0"},
		"Accept-Language": {"en-US"},
	}

	applyBrowserDefaults(req, defaults)

	assert.Equal(t, "TestBrowser/1.0", req.Header.Get("User-Agent"))
	assert.Equal(t, "en-US", req.Header.Get("Accept-Language"))
}

func TestApplyBrowserDefaultsPreservesExisting(t *testing.T) {
	t.Parallel()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	req.Header.Set("User-Agent", "my-custom-ua")

	defaults := http.Header{
		"User-Agent":      {"TestBrowser/1.0"},
		"Accept-Language": {"en-US"},
	}

	applyBrowserDefaults(req, defaults)

	assert.Equal(t, "my-custom-ua", req.Header.Get("User-Agent"))
	assert.Equal(t, "en-US", req.Header.Get("Accept-Language"))
}

func TestApplyBrowserDefaultsNilIsNoop(t *testing.T) {
	t.Parallel()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	applyBrowserDefaults(req, nil)

	assert.Empty(t, req.Header.Get("User-Agent"))
}
