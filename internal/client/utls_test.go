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
	assert.Contains(t, p.headers.Get("User-Agent"), "Chrome")
}

func TestResolveBrowserProfileFirefox(t *testing.T) {
	t.Parallel()

	p, err := resolveBrowserProfile("Firefox")
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Contains(t, p.headers.Get("User-Agent"), "Firefox")
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
