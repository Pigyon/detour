package confirm

import (
	"net/url"
	"strings"
	"sync"

	"github.com/nedlir/detour/internal/scope"
)

// Hop is one step the browser took or tried to take.
type Hop struct {
	URL string `json:"url"`
	// Kind is how the hop was observed: a request, a server redirect, a frame
	// navigation, or an intent detour refused to let out.
	Kind string `json:"kind"`
}

// Hop kinds.
const (
	HopRequest  = "request"
	HopRedirect = "redirect"
	HopFrame    = "frame"
	HopBlocked  = "blocked"
)

// recorder accumulates the navigation chain and, crucially, the destination
// the browser intended to reach before detour stopped it.
//
// The recorded destination is always a captured intent, never a page that
// loaded. That is the whole point: detour proves where a browser was going
// without ever sending the request.
type recorder struct {
	mu       sync.Mutex
	guard    *scope.Guard
	canary   string
	chain    []Hop
	intended string
	blocked  []string
}

func newRecorder(guard *scope.Guard, canary string) *recorder {
	return &recorder{
		guard:   guard,
		canary:  normalizeHost(canary),
		chain:   []Hop{},
		blocked: []string{},
	}
}

// shouldBlock decides whether a request may leave the browser, and captures
// the intended target first when it may not.
//
// This extends the scope guard to the browser's own network stack. Without it,
// Chrome would resolve and contact the canary directly, outside every check
// detour's HTTP client performs.
func (r *recorder) shouldBlock(rawURL string) bool {
	host := hostOf(rawURL)
	if host == "" {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	switch {
	case r.isCanary(host):
		// Capture before refusing: the intent is the evidence.
		if r.intended == "" {
			r.intended = rawURL
		}

		r.blocked = append(r.blocked, rawURL)
		r.chain = append(r.chain, Hop{URL: rawURL, Kind: HopBlocked})

		return true
	case r.guard != nil && !r.guard.Allows(host):
		r.blocked = append(r.blocked, rawURL)
		r.chain = append(r.chain, Hop{URL: rawURL, Kind: HopBlocked})

		return true
	default:
		return false
	}
}

// isCanary matches the canary host and anything under it, so a payload
// wearing a subdomain still counts.
func (r *recorder) isCanary(host string) bool {
	if r.canary == "" {
		return false
	}

	return host == r.canary || strings.HasSuffix(host, "."+r.canary)
}

func (r *recorder) add(rawURL, kind string) {
	if rawURL == "" || strings.HasPrefix(rawURL, "about:") || strings.HasPrefix(rawURL, "data:") {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.chain = append(r.chain, Hop{URL: rawURL, Kind: kind})
}

// result freezes what was observed.
func (r *recorder) result() (intended string, chain []Hop, blocked []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.intended, append([]Hop{}, r.chain...), append([]string{}, r.blocked...)
}

// reachedCanary reports whether the browser tried to leave for the canary.
func (r *recorder) reachedCanary() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.intended != ""
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	return normalizeHost(u.Hostname())
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(host), "."))
}
