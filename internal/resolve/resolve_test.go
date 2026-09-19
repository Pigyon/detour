package resolve_test

import (
	"testing"

	"github.com/nedlir/detour/internal/resolve"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	loopbackV4  = "127.0.0.1"
	attackerURL = "https://evil.example/"
)

func TestRFC3986Resolve(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		base string
		loc  string
		host string
		path string
	}{
		{
			name: "absolute",
			base: "https://app.example/a",
			loc:  "https://evil.example/x",
			host: "evil.example",
			path: "/x",
		},
		{
			name: "relative path",
			base: "https://app.example/dir/page",
			loc:  "../out",
			host: "app.example",
			path: "/out",
		},
		{
			name: "protocol relative",
			base: "https://app.example/a",
			loc:  "//canary.invalid/z",
			host: "canary.invalid",
			path: "/z",
		},
		{
			name: "userinfo",
			base: "https://app.example/a",
			loc:  "https://allowed.lab@canary.invalid/",
			host: "canary.invalid",
			path: "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			u, err := resolve.RFC3986(tt.base, tt.loc)
			require.NoError(t, err)
			assert.Equal(t, tt.host, u.Hostname())
			assert.Equal(t, tt.path, u.Path)
		})
	}
}

func TestBrowserBackslashIsProtocolRelative(t *testing.T) {
	t.Parallel()

	pair, err := resolve.Interpret("https://app.example/go", `/\canary.invalid/`)
	require.NoError(t, err)
	assert.Equal(t, "app.example", pair.RFC.Host)
	assert.Equal(t, "canary.invalid", pair.Browser.Host)
	assert.True(t, resolve.NeedsBrowserConfirm("https://app.example/go", "canary.invalid", pair))
	assert.True(t, resolve.HitsCanary(pair, "canary.invalid"))
}

func TestCanonicalHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "lower", in: "EXAMPLE.COM", want: "example.com"},
		{name: "decimal ipv4", in: "2130706433", want: loopbackV4},
		{name: "hex ipv4", in: "0x7f000001", want: loopbackV4},
		{name: "dotted", in: loopbackV4, want: loopbackV4},
		{name: "idn", in: "exämple.com", want: "xn--exmple-cua.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, resolve.CanonicalHost(tt.in))
		})
	}
}

func TestSameHostAndSuffix(t *testing.T) {
	t.Parallel()

	assert.True(t, resolve.SameHost("EXAMPLE.com", "example.com"))
	assert.True(t, resolve.SameHost("2130706433", loopbackV4))
	assert.True(t, resolve.HostSuffix("app.example.com", "example.com"))
	assert.False(t, resolve.HostSuffix("example.com.evil.example", "example.com"))
	assert.True(t, resolve.HostSuffix("example.com", "example.com"))
}

func TestParseRefresh(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "basic", in: "0;url=" + attackerURL, want: attackerURL, ok: true},
		{name: "spaced url", in: "0; URL=" + attackerURL, want: attackerURL, ok: true},
		{name: "quoted", in: `0;url="` + attackerURL + `"`, want: attackerURL, ok: true},
		{name: "empty", in: "", ok: false},
		{name: "no url", in: "5", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := resolve.ParseRefresh(tt.in)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLocationsFromRaw(t *testing.T) {
	t.Parallel()

	raw := []byte("HTTP/1.1 302 Found\r\nLocation: /safe\r\nLocation: " + attackerURL + "\r\n\r\nbody")
	locs := resolve.LocationsFromRaw(raw)
	require.Equal(t, []string{"/safe", attackerURL}, locs)
}

func TestOffOrigin(t *testing.T) {
	t.Parallel()

	pair, err := resolve.Interpret("https://app.example/a", attackerURL)
	require.NoError(t, err)
	assert.True(t, resolve.OffOrigin("https://app.example/a", pair))
	assert.False(t, resolve.NeedsBrowserConfirm("https://app.example/a", "canary.invalid", pair))
}

func FuzzRFC3986(f *testing.F) {
	f.Add("https://app.example/a", attackerURL)
	f.Add("https://app.example/a", "//canary.invalid")
	f.Add("https://app.example/a", `/\evil.com`)
	f.Add("https://app.example/a", "")
	f.Add("", "https://x.example/")

	f.Fuzz(func(_ *testing.T, base, loc string) {
		_, _ = resolve.RFC3986(base, loc)
		_, _ = resolve.Browser(base, loc)
		_, _ = resolve.Interpret(base, loc)
	})
}
