package surface_test

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/nedlir/detour/internal/surface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubEnum struct{ hosts []string }

func (s stubEnum) Enumerate(context.Context, string) ([]string, error) { return s.hosts, nil }

type failingEnum struct{}

func (failingEnum) Enumerate(context.Context, string) ([]string, error) {
	return nil, errors.New("source unavailable")
}

type stubResolver struct{ cnames map[string]string }

func (s stubResolver) Resolve(_ context.Context, host string) ([]string, string, error) {
	return []string{"192.0.2.1"}, s.cnames[host], nil
}

type stubProber struct{ live map[string]int }

func (s stubProber) Probe(_ context.Context, host string) (surface.Host, error) {
	status, ok := s.live[host]
	if !ok {
		return surface.Host{Host: host}, nil
	}

	return surface.Host{Host: host, URL: "https://" + host, Status: status, Title: "t"}, nil
}

// TestSurfaceFlagsVendorDelegation is the signal the stage exists for.
func TestSurfaceFlagsVendorDelegation(t *testing.T) {
	t.Parallel()

	m := surface.New(surface.Options{
		Enumerator: stubEnum{hosts: []string{"mail.a.lab", "www.a.lab", "cdn.a.lab"}},
		Resolver: stubResolver{cnames: map[string]string{
			"mail.a.lab": "u123.wl.sendgrid.net",
			"cdn.a.lab":  "x.cloudfront.net",
		}},
		Prober: stubProber{live: map[string]int{"mail.a.lab": 200, "www.a.lab": 200}},
	})

	result := m.Run(context.Background(), "a.lab")

	require.NotEmpty(t, result.Hosts)
	assert.Equal(t, "mail.a.lab", result.Hosts[0].Host, "vendor-delegated hosts sort first")
	assert.Equal(t, "sendgrid", result.Hosts[0].Vendor)

	priority := result.Priority()
	require.Len(t, priority, 1)
	assert.Equal(t, "mail.a.lab", priority[0].Host)

	assert.Equal(t, []string{"https://mail.a.lab", "https://www.a.lab"}, result.Origins())
}

func TestSurfaceKeepsEnumerationFailures(t *testing.T) {
	t.Parallel()

	m := surface.New(surface.Options{
		Enumerator: failingEnum{},
		Resolver:   stubResolver{cnames: map[string]string{}},
		Prober:     stubProber{live: map[string]int{"a.lab": 200}},
	})

	result := m.Run(context.Background(), "a.lab")

	require.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0], "enumerate")
	assert.Len(t, result.Hosts, 1, "the apex is still inspected")
}

func TestSurfaceDedupesAndIncludesApex(t *testing.T) {
	t.Parallel()

	m := surface.New(surface.Options{
		Enumerator: stubEnum{hosts: []string{"A.LAB", "a.lab", "www.a.lab.", ""}},
		Resolver:   stubResolver{cnames: map[string]string{}},
		Prober:     stubProber{live: map[string]int{}},
	})

	result := m.Run(context.Background(), "a.lab")

	hosts := []string{}
	for _, h := range result.Hosts {
		hosts = append(hosts, h.Host)
	}

	assert.Equal(t, []string{"a.lab", "www.a.lab"}, hosts)
}

func TestSurfaceWorksWithStagesMissing(t *testing.T) {
	t.Parallel()

	result := surface.New(surface.Options{}).Run(context.Background(), "a.lab")

	require.Len(t, result.Hosts, 1)
	assert.Equal(t, "a.lab", result.Hosts[0].Host)
	assert.False(t, result.Hosts[0].Live())
	assert.Empty(t, result.Origins())
}

// recordingProber notes every host that was actually contacted.
type recordingProber struct {
	mu    sync.Mutex
	hosts []string
}

func (r *recordingProber) Probe(_ context.Context, host string) (surface.Host, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.hosts = append(r.hosts, host)

	return surface.Host{Host: host, Status: 200}, nil
}

func (r *recordingProber) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := append([]string(nil), r.hosts...)
	sort.Strings(out)

	return out
}

// TestRunRefusesOutOfScopeHosts is the regression for the one stage that sent
// requests without asking the scope guard. Enumeration returns whatever the
// sources hold, which for a large organization routinely includes hosts
// outside the engagement.
func TestRunRefusesOutOfScopeHosts(t *testing.T) {
	t.Parallel()

	prober := &recordingProber{}

	mapper := surface.New(surface.Options{
		Enumerator: stubEnum{hosts: []string{"in.example", "out.other", "also.other"}},
		Prober:     prober,
		Allow:      func(host string) bool { return strings.HasSuffix(host, ".example") },
	})

	result := mapper.Run(context.Background(), "in.example")

	assert.Equal(t, []string{"in.example"}, prober.seen(), "only in-scope hosts may be contacted")
	assert.Contains(t, strings.Join(result.Errors, " "), "out of scope")
}
