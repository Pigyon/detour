package attack

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()

	parsed, err := url.Parse(raw)
	require.NoError(t, err)

	return parsed
}

// TestIsInternalHost guards the rule that keeps internal hosts out of
// payloads. A string-prefix test got this wrong in both directions, and a name
// such as metadata.google.internal reaches a metadata service without being
// written as an address at all.
func TestIsInternalHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		host string
		want bool
	}{
		{name: "loopback", host: "127.0.0.1", want: true},
		{name: "loopback elsewhere in the range", host: "127.5.5.5", want: true},
		{name: "ipv6 loopback", host: "::1", want: true},
		{name: "link local carries the metadata endpoint", host: "169.254.169.254", want: true},
		{name: "ipv6 link local", host: "fe80::1", want: true},
		{name: "private ten", host: "10.0.0.1", want: true},
		{name: "private 172.16, which a prefix test missed", host: "172.16.0.1", want: true},
		{name: "private 172.31", host: "172.31.255.1", want: true},
		{name: "private 192.168", host: "192.168.1.1", want: true},
		{name: "unique local ipv6", host: "fd00::1", want: true},
		{name: "unspecified", host: "0.0.0.0", want: true},

		{name: "carrier grade nat is not private", host: "100.64.0.1", want: false},
		{name: "public", host: "93.184.216.34", want: false},
		{name: "172.32 is outside the private range", host: "172.32.0.1", want: false},
		{name: "a name that starts like a private range", host: "10.example.com", want: false},
		{name: "a name that starts like loopback", host: "127.0.0.1.nip.io", want: false},
		{name: "a name that starts like 192.168", host: "192.168.example.com", want: false},
		{name: "an ordinary name", host: "google.com", want: false},
		{name: "empty", host: "", want: false},

		{name: "localhost", host: "localhost", want: true},
		{name: "a name under .internal", host: "metadata.google.internal", want: true},
		{name: "a name under .localhost", host: "api.localhost", want: true},
		{name: "mdns", host: "printer.local", want: true},
		{name: "a trailing dot does not hide it", host: "localhost.", want: true},
		{name: "a name merely containing internal", host: "internal.example.com", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, isInternalHost(tt.host))
		})
	}
}

// TestTrustedHostRefusesInternalAddresses is the regression for a payload that
// handed a target back an address out of its own parameter.
func TestTrustedHostRefusesInternalAddresses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		source  string
		current string
		want    string
	}{
		{
			name:    "an ordinary value is trusted",
			source:  "https://app.example/r?url=x",
			current: "https://cdn.example/a.png",
			want:    "cdn.example",
		},
		{
			name:    "loopback in the value is refused",
			source:  "https://app.example/r?img=x",
			current: "http://127.0.0.1:8080/x",
			want:    "app.example",
		},
		{
			name:    "the metadata endpoint is refused",
			source:  "https://app.example/r?next=x",
			current: "http://169.254.169.254/latest/meta-data/",
			want:    "app.example",
		},
		{
			// The target is on a private range, which is ordinary when testing
			// an internal application. Its own host is still usable; the other
			// private host in the parameter is not.
			name:    "the target's own internal host is still usable",
			source:  "http://10.0.0.5/r?url=x",
			current: "http://192.168.1.1/",
			want:    "10.0.0.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			parsed := mustParse(t, tt.source)
			assert.Equal(t, tt.want, trustedHost(parsed, tt.current))
		})
	}
}

// TestSafeValueRefusesInternalAuthority is the regression for the value token.
// It carries the parameter's current value verbatim so a containment allowlist
// sees a whole trusted URL, which also meant handing a target back an internal
// address it could reach.
func TestSafeValueRefusesInternalAuthority(t *testing.T) {
	t.Parallel()

	const origin = "app.example"

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "an ordinary destination", value: "https://cdn.example/a.png", want: true},
		{name: "a relative value has no authority", value: "/account", want: true},
		{name: "the metadata endpoint", value: "http://169.254.169.254/latest/meta-data/", want: false},
		{name: "loopback with a port", value: "http://127.0.0.1:8080/x", want: false},
		{name: "a private range", value: "http://10.0.0.7/", want: false},
		{name: "localhost by name", value: "http://localhost/admin", want: false},
		{name: "an encoded loopback", value: "http://2130706433/", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, safeValue(tt.value, origin))
		})
	}
}

// TestSafeHostAllowsTheTargetItself keeps the rule from blocking ordinary
// work. Testing an application on localhost or a private range is normal, and
// telling a target its own address escalates nothing: it is already there.
func TestSafeHostAllowsTheTargetItself(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "127.0.0.1", safeHost("127.0.0.1", "127.0.0.1"))
	assert.Equal(t, "10.0.0.5", safeHost("10.0.0.5", "10.0.0.5"))

	// A different internal host is detour asking one machine to reach another.
	assert.Empty(t, safeHost("169.254.169.254", "127.0.0.1"))
	assert.Empty(t, safeHost("10.0.0.7", "app.example"))

	assert.Equal(t, "cdn.example", safeHost("cdn.example", "app.example"))
}
