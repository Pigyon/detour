// Package scope enforces the host allow/deny boundary and the canary hard-stop.
package scope

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/nedlir/detour/internal/resolve"
)

var (
	// ErrOutOfScope is returned when a host is not in the configured scope.
	ErrOutOfScope = errors.New("out of scope")

	// ErrCanary is returned when a host is the canary (never contacted).
	ErrCanary = errors.New("canary host")
)

// Guard is the bottom-of-stack check for every outbound request.
type Guard struct {
	allows  []hostRule
	denies  []hostRule
	canary  string
	refused []string
}

type hostRule struct {
	host       string
	isWildcard bool
}

// New returns a guard that denies only the canary when no allow rules exist.
func New(canary string) *Guard {
	return &Guard{
		allows: []hostRule{},
		denies: []hostRule{},
		canary: normalizeHost(canary),
	}
}

// Parse builds a guard from bounty-style scope lines.
//
//	example.com
//	*.example.com
//	https://app.example.com/path
//	!out.example.com
func Parse(lines []string, canary string) (*Guard, error) {
	g := New(canary)

	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		deny := false
		if strings.HasPrefix(line, "!") {
			deny = true
			line = strings.TrimSpace(strings.TrimPrefix(line, "!"))
		}

		rule, err := parseRule(line)
		if err != nil {
			return nil, fmt.Errorf("scope line %d: %w", i+1, err)
		}

		if deny {
			g.denies = append(g.denies, rule)
			continue
		}

		g.allows = append(g.allows, rule)
	}

	return g, nil
}

// LoadFile reads a scope file and returns a guard.
func LoadFile(path, canary string) (g *Guard, err error) {
	file, openErr := os.Open(path) //nolint:gosec // G304: path is the operator-supplied --scope-file.
	if openErr != nil {
		return nil, fmt.Errorf("opening scope file: %w", openErr)
	}

	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing scope file: %w", cerr)
		}
	}()

	lines := []string{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if scanErr := scanner.Err(); scanErr != nil {
		return nil, fmt.Errorf("reading scope file: %w", scanErr)
	}

	return Parse(lines, canary)
}

// Check reports whether host may be contacted.
func (g *Guard) Check(host string) error {
	normalized := normalizeHost(host)
	if normalized == "" {
		return fmt.Errorf("empty host: %w", ErrOutOfScope)
	}

	if g.isCanary(normalized) {
		return fmt.Errorf("%s: %w", normalized, ErrCanary)
	}

	if g.matches(g.denies, normalized) {
		return fmt.Errorf("%s: %w", normalized, ErrOutOfScope)
	}

	if len(g.allows) == 0 {
		return nil
	}

	if g.matches(g.allows, normalized) {
		return nil
	}

	return fmt.Errorf("%s: %w", normalized, ErrOutOfScope)
}

// CheckURL extracts the host from rawURL and checks it.
func (g *Guard) CheckURL(rawURL string) error {
	host, err := HostOf(rawURL)
	if err != nil {
		return err
	}

	return g.Check(host)
}

// Allows is true when Check would return nil.
func (g *Guard) Allows(host string) bool {
	return g.Check(host) == nil
}

// HostOf returns the hostname (no port) of rawURL.
func HostOf(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parsing url: %w", err)
	}

	if parsed.Host == "" && parsed.Path != "" && !strings.Contains(rawURL, "://") {
		parsed, err = url.Parse("https://" + rawURL)
		if err != nil {
			return "", fmt.Errorf("parsing host: %w", err)
		}
	}

	host := parsed.Hostname()
	if host == "" {
		return "", fmt.Errorf("url %q has no host: %w", rawURL, ErrOutOfScope)
	}

	return normalizeHost(host), nil
}

// isCanary refuses the redirect destination and everything under it.
//
// The subdomain half matters. Detection counts a subdomain as a hit, because
// several techniques land on allowed.example.destination rather than on the
// destination itself, and whoever holds a domain holds every name beneath it.
// A guard that only refused the exact host would therefore let detour request
// the very names its own payloads aim at, with the operator's credentials
// attached. That was inert while the destination was a non-resolving .invalid
// name and is not inert now that it can be a real domain.
func (g *Guard) isCanary(host string) bool {
	if under(host, g.canary) {
		return true
	}

	for _, extra := range g.refused {
		if under(host, extra) {
			return true
		}
	}

	return false
}

// under reports whether host is name or sits beneath it.
func under(host, name string) bool {
	return name != "" && (host == name || strings.HasSuffix(host, "."+name))
}

// Refuse adds a destination the guard will never contact, alongside the
// primary one. The second probe of the input_controlled check points at its
// own host, and that host is no more ours to request than the first.
func (g *Guard) Refuse(host string) {
	host = normalizeHost(host)
	if host == "" {
		return
	}

	g.refused = append(g.refused, host)
}

func (g *Guard) matches(rules []hostRule, host string) bool {
	for _, rule := range rules {
		if rule.isWildcard {
			if host == rule.host {
				continue
			}

			if strings.HasSuffix(host, "."+rule.host) {
				return true
			}

			continue
		}

		if host == rule.host {
			return true
		}
	}

	return false
}

func parseRule(line string) (hostRule, error) {
	isWildcard := false
	if strings.HasPrefix(line, "*.") {
		isWildcard = true
		line = strings.TrimPrefix(line, "*.")
	}

	if strings.Contains(line, "://") {
		host, err := HostOf(line)
		if err != nil {
			return hostRule{}, err
		}

		line = host
	}

	host := normalizeHost(line)
	if host == "" {
		return hostRule{}, errors.New("empty host rule")
	}

	return hostRule{host: host, isWildcard: isWildcard}, nil
}

// normalizeHost reduces a host to the form the guard compares.
//
// It ends by handing the result to resolve.CanonicalHost, so the guard and the
// detection side agree on what a host is. They did not, and the disagreement
// was exploitable: a trailing dot is a legal, fully equivalent way to write a
// fully qualified name, and "google.com." reached the network while
// "google.com" was refused.
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "*.")
	host = strings.ToLower(host)

	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")

	// A name may carry several trailing dots and still resolve.
	host = strings.TrimRight(host, ".")

	return resolve.CanonicalHost(host)
}
