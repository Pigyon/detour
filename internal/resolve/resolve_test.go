package resolve_test

import (
	"testing"

	"github.com/nedlir/detour/internal/resolve"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	namedHost   = "allowed.example"
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

	lf := []byte("HTTP/1.1 302 Found\nLocation: /safe\nLocation: " + attackerURL + "\n\nbody")
	assert.Equal(t, []string{"/safe", attackerURL}, resolve.LocationsFromRaw(lf))
}

func FuzzLocationsFromRaw(f *testing.F) {
	f.Add([]byte("HTTP/1.1 302 Found\r\nLocation: /safe\r\nLocation: https://evil.example/\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"))
	f.Add([]byte("Location: https://a.example/\nLocation: https://b.example/\n\n"))

	f.Fuzz(func(_ *testing.T, raw []byte) {
		if len(raw) > 1<<16 {
			return
		}

		_ = resolve.LocationsFromRaw(raw)
	})
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

// TestCanonicalHostAddressEncodings is the OR-A15 half of the resolver: every
// spelling of an address has to reduce to one dotted quad, or an allowlist
// comparison upstream is comparing strings rather than destinations.
func TestCanonicalHostAddressEncodings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		host string
		want string
	}{
		{name: "dotted quad is already canonical", host: loopbackV4, want: loopbackV4},
		{name: "decimal", host: "2130706433", want: loopbackV4},
		{name: "hex", host: "0x7f000001", want: loopbackV4},
		{name: "octal", host: "0177.0.0.1", want: loopbackV4},
		{name: "two part", host: "127.1", want: loopbackV4},
		{name: "mixed radix two part", host: "0x7f.1", want: loopbackV4},
		{name: "ipv4 mapped ipv6", host: "::ffff:127.0.0.1", want: loopbackV4},
		{name: "link local decimal", host: "2852039166", want: "169.254.169.254"},
		{name: "link local octal", host: "0251.0376.0251.0376", want: "169.254.169.254"},
		{name: "a name is left alone", host: namedHost, want: namedHost},
		{name: "a name of digits and dots that is not an address", host: "1.2.3.4.5", want: "1.2.3.4.5"},
		{name: "octet out of range is not an address", host: "999.0.0.1", want: "999.0.0.1"},
		{name: "trailing dot is not an address", host: loopbackV4 + ".", want: loopbackV4},
		{name: "empty", host: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, resolve.CanonicalHost(tt.host))
		})
	}
}

// TestSameHostAcrossEncodings is the property the technique actually turns on.
func TestSameHostAcrossEncodings(t *testing.T) {
	t.Parallel()

	for _, encoded := range []string{"2130706433", "0x7f000001", "0177.0.0.1", "127.1"} {
		assert.True(t, resolve.SameHost(loopbackV4, encoded), "%s must equal %s", encoded, loopbackV4)
	}

	assert.False(t, resolve.SameHost(loopbackV4, "2130706434"))
}

// TestMetaRefreshAttributeForms covers what browsers accept. An unquoted
// content attribute navigates exactly like a quoted one, and a page may carry
// more than one refresh tag.
func TestMetaRefreshAttributeForms(t *testing.T) {
	t.Parallel()

	const want = "https://c.invalid/"

	tests := []struct {
		name string
		body string
	}{
		{name: "double quoted", body: `<meta http-equiv="refresh" content="0;url=` + want + `">`},
		{name: "single quoted", body: `<meta http-equiv='refresh' content='0;url=` + want + `'>`},
		{name: "unquoted", body: `<meta http-equiv=refresh content=0;url=` + want + `>`},
		{name: "attributes reversed", body: `<meta content=0;url=` + want + ` http-equiv=refresh>`},
		{name: "not the first tag", body: `<meta charset=utf-8><meta http-equiv=refresh content="1;url=` + want + `">`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := resolve.MetaRefresh([]byte(tt.body))
			require.True(t, ok)
			assert.Equal(t, []string{want}, got)
		})
	}
}

func TestMetaRefreshIgnoresOtherTags(t *testing.T) {
	t.Parallel()

	_, ok := resolve.MetaRefresh([]byte(`<meta name=description content="0;url=https://c.invalid/">`))
	assert.False(t, ok, "only a refresh directive navigates")
}

// TestParseRefreshOffsetIsTakenOnTheOriginal is the regression for an index
// computed on a lowercased copy. strings.ToLower can change a string's byte
// length, so such an index points at the wrong place, or past the end.
func TestParseRefreshOffsetIsTakenOnTheOriginal(t *testing.T) {
	t.Parallel()

	const dest = "https://c.invalid/"

	tests := []struct {
		name   string
		header string
	}{
		{name: "plain", header: "0;url=" + dest},
		{name: "uppercase directive", header: "0;URL=" + dest},
		{name: "mixed case", header: "0;UrL=" + dest},
		{name: "space after the directive", header: "0;URL= " + dest},
		{name: "a rune whose lowercase is a different byte length", header: "0;\u0130\u0130URL=" + dest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := resolve.ParseRefresh(tt.header)
			require.True(t, ok)
			assert.Equal(t, dest, got)
		})
	}
}

// TestMetaRefreshIgnoresInertMarkup keeps detour from reporting a tag a
// browser never parses as one.
func TestMetaRefreshIgnoresInertMarkup(t *testing.T) {
	t.Parallel()

	const tag = `<meta http-equiv="refresh" content="0;url=https://c.invalid/">`

	tests := []struct {
		name string
		body string
	}{
		{name: "inside a comment", body: `<!-- ` + tag + ` -->`},
		{name: "inside a script string", body: `<script>var s='` + tag + `';</script>`},
		{name: "inside a textarea", body: `<textarea>` + tag + `</textarea>`},
		{name: "inside a template", body: `<template>` + tag + `</template>`},
		{name: "a different http-equiv", body: `<meta http-equiv="refresh-policy" content="0;url=https://c.invalid/">`},
		{name: "a different tag name", body: `<metafoo http-equiv=refresh content=0;url=https://c.invalid/>`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, ok := resolve.MetaRefresh([]byte(tt.body))
			assert.False(t, ok, "this navigates nothing: %s", tt.body)
		})
	}
}

// TestMetaRefreshReturnsEveryDestination is the regression for returning only
// the first. A benign refresh ahead of the attacker-controlled one used to
// hide the finding entirely.
func TestMetaRefreshReturnsEveryDestination(t *testing.T) {
	t.Parallel()

	body := `<meta http-equiv=refresh content="0;url=/safe">` +
		`<meta http-equiv=refresh content="1;url=https://c.invalid/">`

	got, ok := resolve.MetaRefresh([]byte(body))
	require.True(t, ok)
	assert.Equal(t, []string{"/safe", "https://c.invalid/"}, got)
}

// TestMetaRefreshOrderingAndRegions pins the cases an adversarial review found:
// a comment opener inside a script string must not swallow a real tag, an
// unterminated region must run to the end the way a browser reads it, and a
// missing space between attributes is a recoverable parse error that browsers
// act on.
func TestMetaRefreshOrderingAndRegions(t *testing.T) {
	t.Parallel()

	const dest = "https://c.invalid/"

	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "a comment opener inside a script string is not a comment",
			body: `<script>x = "<!--"</script><meta http-equiv=refresh content="0;url=` + dest + `"><!-- tail -->`,
			want: true,
		},
		{
			name: "no space between attributes still navigates",
			body: `<meta http-equiv="refresh"content="0;url=` + dest + `">`,
			want: true,
		},
		{
			name: "an unterminated comment hides everything after it",
			body: `<!-- <meta http-equiv=refresh content="0;url=` + dest + `">`,
			want: false,
		},
		{
			name: "a tag inside a style block is text",
			body: `<style>/*<meta http-equiv=refresh content="0;url=` + dest + `">*/</style>`,
			want: false,
		},
		{
			name: "an unterminated script hides everything after it",
			body: `<script>var s = "<meta http-equiv=refresh content='0;url=` + dest + `'>"`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := resolve.MetaRefresh([]byte(tt.body))
			assert.Equal(t, tt.want, ok, "got %v", got)

			if tt.want {
				assert.Equal(t, []string{dest}, got)
			}
		})
	}
}

// TestParseRefreshKeepsQuotesOwnedByTheValue is the regression for trimming
// both quote characters off both ends.
func TestParseRefreshKeepsQuotesOwnedByTheValue(t *testing.T) {
	t.Parallel()

	got, ok := resolve.ParseRefresh(`0;url=/x?a='b'`)
	require.True(t, ok)
	assert.Equal(t, `/x?a='b'`, got)

	quoted, ok := resolve.ParseRefresh(`0;url="https://c.invalid/"`)
	require.True(t, ok)
	assert.Equal(t, "https://c.invalid/", quoted)
}
