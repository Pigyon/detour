package attack

import (
	"net"
	"net/url"
	"strings"

	"github.com/nedlir/detour/internal/resolve"
)

// detour must never aim a payload at an internal address, and must never hand
// one back to a target that can reach it. That is the internal-address step:
// the operator's call on an authorized target, never a scanner's.
//
// Every place a host is taken from input and put back into a payload goes
// through safeHost. There are four of them (the parameter's current value, a
// field inside a decoded envelope, the source URL itself, and the verbatim
// value token), and fixing three of them is the same as fixing none.

// internalNames are hosts that resolve to an internal service without being
// written as an address. metadata.google.internal is the GCP metadata
// endpoint; .internal and .localhost are reserved for exactly this.
var internalNames = []string{"localhost", ".localhost", ".internal", ".local"}

// isInternalHost reports whether a host reaches something detour must not aim
// a target at.
//
// Addresses are parsed rather than prefix-matched, because a prefix test calls
// 10.example.com internal and misses 172.16.0.0/12 entirely.
func isInternalHost(host string) bool {
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}

	if ip := net.ParseIP(resolve.CanonicalHost(host)); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() ||
			ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
			ip.IsUnspecified()
	}

	for _, name := range internalNames {
		if host == strings.TrimPrefix(name, ".") || strings.HasSuffix(host, name) {
			return true
		}
	}

	return false
}

// safeHost returns host unless aiming a payload at it would be the
// internal-address step.
//
// The target's own host is always allowed, whatever it is. Testing an
// application on localhost or on a private range is ordinary work, and there
// is no escalation in telling a target its own address: it is already there.
// What is refused is an internal host that is not the target, because that is
// detour asking one host to reach another.
func safeHost(host, origin string) string {
	if !isInternalHost(host) || sameHost(host, origin) {
		return host
	}

	return ""
}

// sameHost compares two hosts the way the rest of the tool does.
func sameHost(a, b string) bool {
	ca, cb := resolve.CanonicalHost(a), resolve.CanonicalHost(b)

	return ca != "" && ca == cb
}

// safeValue reports whether a parameter's current value can be carried into a
// payload verbatim.
//
// The value token exists so a containment allowlist sees a whole trusted URL,
// but it is attacker-influenced input echoed back at the target. A value whose
// authority is internal would have detour ask the target to reach it, which is
// the same step by a different route.
func safeValue(value, origin string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return false
	}

	return safeHost(parsed.Hostname(), origin) == parsed.Hostname()
}
