package attack_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/nedlir/detour/internal/attack"
	"github.com/nedlir/detour/internal/client"
	"github.com/nedlir/detour/internal/config"
	"github.com/nedlir/detour/internal/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// paramURL is the destination parameter these fixtures use.
const paramURL = "url"

func TestChainTargetsFrom(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		urls []string
		want []attack.ChainTarget
	}{
		{
			name: "a redirect parameter makes an endpoint a second leg",
			urls: []string{"https://app.example/go?url=https://app.example/home"},
			want: []attack.ChainTarget{{Path: "/go", Param: paramURL}},
		},
		{
			name: "the same endpoint is only offered once",
			urls: []string{
				"https://app.example/go?url=a",
				"https://app.example/go?url=b",
			},
			want: []attack.ChainTarget{{Path: "/go", Param: paramURL}},
		},
		{
			name: "a host-shaped parameter cannot carry a nested url",
			urls: []string{"https://app.example/next?destHost=app.example"},
			want: []attack.ChainTarget{},
		},
		{
			name: "a static hop with a redirector-shaped name is a candidate",
			urls: []string{"https://app.example/f07/r1"},
			want: []attack.ChainTarget{{Path: "/f07/r1"}},
		},
		{
			name: "a plain page is not a static hop",
			urls: []string{"https://app.example/about"},
			want: []attack.ChainTarget{},
		},
		{
			name: "a redirector-shaped path outranks a plain one",
			urls: []string{
				"https://app.example/profile?url=x",
				"https://app.example/go/inner?url=x",
			},
			want: []attack.ChainTarget{
				{Path: "/go/inner", Param: paramURL},
				{Path: "/profile", Param: paramURL},
			},
		},
		{
			name: "an endpoint with no destination parameter is not a redirector",
			urls: []string{"https://app.example/about?page=2"},
			want: []attack.ChainTarget{},
		},
		{
			name: "unparseable input is skipped rather than fatal",
			urls: []string{"://nonsense", "https://app.example/r?next=x"},
			want: []attack.ChainTarget{{Path: "/r", Param: "next"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, attack.ChainTargetsFrom(tt.urls))
		})
	}
}

// TestChainTargetsFromStaysBounded keeps the second leg from turning a run
// quadratic: every target costs a probe against every outer parameter.
func TestChainTargetsFromStaysBounded(t *testing.T) {
	t.Parallel()

	urls := make([]string, 0, 50)
	for i := range 50 {
		urls = append(urls, "https://app.example/r"+string(rune('a'+i%26))+string(rune('a'+i/26))+"?url=x")
	}

	assert.LessOrEqual(t, len(attack.ChainTargetsFrom(urls)), 8)
}

// TestTargetParamsFindsURLValuedNames is the pipeline hole this closes: the
// classifier calls a url-valued parameter the strongest signal there is, and
// the engine used to attack only parameters whose NAME it recognized.
func TestTargetParamsFindsURLValuedNames(t *testing.T) {
	t.Parallel()

	// "q" is in no redirect-parameter list anywhere.
	eng, srv := echoEngine(t, "q")

	findings, err := eng.Run(
		context.Background(),
		[]string{srv.URL + "/search?q=" + url.QueryEscape("https://allowed.example/")},
	)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "a parameter already holding a url must be attacked whatever it is called")

	for _, f := range findings {
		assert.Equal(t, "q", f.Candidate.ParamName)
	}
}

// TestOrdinaryValuesIgnoredOnANonRedirector keeps the request budget sane:
// an endpoint that never answers with a destination gets only its
// redirect-named and url-valued parameters probed.
func TestOrdinaryValuesIgnoredOnANonRedirector(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	eng := engineFor(t)

	findings, err := eng.Run(context.Background(), []string{srv.URL + "/page?q=2&sort=name"})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// TestRedirectorWidensToEveryParameter is the regression for a live miss.
//
// The firing range serves a meta refresh from "?q=/". The name is not on any
// redirect list and the value is not url shaped, so neither signal fired and
// the endpoint was never probed, even though it plainly redirects. An endpoint
// that already answers with a destination has earned a look at all of its
// parameters.
func TestRedirectorWidensToEveryParameter(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("q")
		if value == "" {
			w.WriteHeader(http.StatusOK)

			return
		}

		w.Header().Set("Location", value)
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	eng := engineFor(t)

	findings, err := eng.Run(context.Background(), []string{srv.URL + "/redirect/meta?q=/"})
	require.NoError(t, err)
	require.NotEmpty(t, findings, "a proven redirector must have every parameter probed")

	for _, f := range findings {
		assert.Equal(t, "q", f.Candidate.ParamName)
	}
}

// engineFor builds an engine for a test server.
func engineFor(t *testing.T) *attack.Engine {
	t.Helper()

	cfg := config.Config{Canary: testCanary, Rate: 300, Concurrency: 4, Timeout: 3 * time.Second}

	c, err := client.New(cfg, scope.New(cfg.Canary))
	require.NoError(t, err)

	return attack.New(c, cfg.Canary, "", cfg.Concurrency, nil)
}

// echoEngine serves an endpoint that redirects to whatever param carries.
func echoEngine(t *testing.T, param string) (*attack.Engine, *httptest.Server) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get(param)
		if value == "" {
			w.WriteHeader(http.StatusOK)

			return
		}

		w.Header().Set("Location", value)
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	cfg := config.Config{Canary: testCanary, Rate: 200, Concurrency: 4, Timeout: 3 * time.Second}
	guard := scope.New(cfg.Canary)
	c, err := client.New(cfg, guard)
	require.NoError(t, err)

	return attack.New(c, cfg.Canary, "", cfg.Concurrency, nil), srv
}
