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
)

var (
	// ErrOutOfScope is returned when a host is not in the configured scope.
	ErrOutOfScope = errors.New("out of scope")

	// ErrCanary is returned when a host is the canary (never contacted).
	ErrCanary = errors.New("canary host")
)

// Guard is the bottom-of-stack check for every outbound request.
type Guard struct {
	allows []hostRule
	denies []hostRule
	canary string
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

func (g *Guard) isCanary(host string) bool {
	if g.canary == "" {
		return false
	}

	return host == g.canary
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

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "*.")
	host = strings.ToLower(host)

	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")

	return host
}
