package attack_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/nedlir/detour/internal/lab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var recallIDs = []string{"OR-A01", "OR-A03", "OR-A07", "OR-A11", "OR-D01"}

func TestLabZeroFalsePositives(t *testing.T) {
	t.Parallel()

	eng, srv := newEngine(t)
	urls := []string{}

	for _, ep := range lab.Catalog() {
		if ep.Kind != lab.KindDecoy {
			continue
		}

		urls = append(urls, srv.URL+catalogProbe(ep))
	}

	blob := lab.SignDest("https://" + lab.AllowedHost + "/home")
	urls = append(urls, srv.URL+"/decoy/signed/"+blob)

	findings, err := eng.Run(context.Background(), urls)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestLabRecall(t *testing.T) {
	t.Parallel()

	eng, srv := newEngine(t)
	urls := []string{}
	want := map[string]struct{}{}

	for _, id := range recallIDs {
		want[id] = struct{}{}
	}

	for _, ep := range lab.Catalog() {
		if _, ok := want[ep.ID]; !ok {
			continue
		}

		urls = append(urls, srv.URL+catalogProbe(ep))
	}

	findings, err := eng.Run(context.Background(), urls)
	require.NoError(t, err)

	got := map[string]struct{}{}

	for _, f := range findings {
		got[f.TechniqueID] = struct{}{}
		assert.True(t, f.Capabilities.InputControlled)
	}

	for id := range want {
		_, ok := got[id]
		assert.True(t, ok, "missing recall for %s", id)
	}
}

func catalogProbe(ep lab.Endpoint) string {
	if ep.Param == "" {
		return ep.Probe
	}

	return ep.Probe + "?" + ep.Param + "=" + url.QueryEscape("https://"+lab.AllowedHost+"/")
}
