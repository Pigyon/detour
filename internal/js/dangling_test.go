package js_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/nedlir/detour/internal/js"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubResolver answers from a fixed table so the dangling pass is testable
// without touching DNS.
type stubResolver struct {
	live    map[string]bool
	timeout map[string]bool
}

func (s stubResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if s.timeout[host] {
		return nil, &net.DNSError{Err: "timeout", Name: host, IsTimeout: true}
	}

	if s.live[host] {
		return []string{"192.0.2.1"}, nil
	}

	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// Hosts shared by the dangling-resolver cases.
const (
	hostLive = "live.lab"
	hostGone = "gone.lab"
)

func TestDanglingHosts(t *testing.T) {
	t.Parallel()

	r := stubResolver{
		live:    map[string]bool{hostLive: true, "cdn." + hostLive: true},
		timeout: map[string]bool{"slow.lab": true},
	}

	tests := []struct {
		name  string
		hosts []string
		want  []string
	}{
		{name: "all live", hosts: []string{hostLive, "cdn." + hostLive}, want: []string{}},
		{name: "one dangling", hosts: []string{hostLive, hostGone}, want: []string{hostGone}},
		{
			name:  "a timeout is not a finding",
			hosts: []string{"slow.lab"},
			want:  []string{},
		},
		{
			name:  "entries are normalized to hosts",
			hosts: []string{"https://gone.lab/path", "*.gone.lab", "GONE.LAB", "gone.lab:8443"},
			want:  []string{hostGone},
		},
		{name: "junk is skipped", hosts: []string{"", "   ", "https://"}, want: []string{}},
		{name: "none", hosts: nil, want: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := js.DanglingHosts(context.Background(), r, tt.hosts)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDanglingVerdicts(t *testing.T) {
	t.Parallel()

	verdicts := js.DanglingVerdicts([]string{hostGone})
	require.Len(t, verdicts, 1)
	assert.Equal(t, "OR-F08", verdicts[0].TechniqueID)
	assert.Equal(t, js.SeverityCandidate, verdicts[0].Severity)
	assert.Contains(t, verdicts[0].Discrepancy, hostGone)
	assert.Equal(t, "https://gone.lab/", verdicts[0].Payload)
}

// TestResolveDanglingUsesGuardAllowlists wires the pass to what the guards
// actually trust.
func TestResolveDanglingUsesGuardAllowlists(t *testing.T) {
	t.Parallel()

	report, err := js.Analyze("t.js", []byte(
		`const hosts = ["live.lab","gone.lab"]; function ok(u){ return hosts.some(d => u.endsWith(d)) } function g(u){ if (ok(u)) location.href = u }`,
	))
	require.NoError(t, err)

	page := js.PageReport{URL: pageURL, Scripts: []js.Report{report}, Verdicts: report.Verdicts}
	assert.ElementsMatch(t, []string{hostLive, hostGone}, page.Allowlists())

	page.ResolveDangling(context.Background(), stubResolver{live: map[string]bool{hostLive: true}})
	assert.Equal(t, []string{hostGone}, page.Dangling)

	_, found := verdictByID(page.Verdicts, "OR-F08")
	assert.True(t, found)
}

func TestDanglingIgnoresNonDNSErrors(t *testing.T) {
	t.Parallel()

	got := js.DanglingHosts(context.Background(), erroringResolver{}, []string{"any.lab"})
	assert.Empty(t, got, "a resolver failure is not evidence a host is unregistered")
}

type erroringResolver struct{}

func (erroringResolver) LookupHost(context.Context, string) ([]string, error) {
	return nil, errors.New("resolver unavailable")
}
