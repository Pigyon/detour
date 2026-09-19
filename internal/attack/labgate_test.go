package attack_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/nedlir/detour/internal/lab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recallIDs are the techniques the server-side engine can reach today. The
// chained-redirector case (OR-B05) needs hop following and is not here yet.
var recallIDs = []string{
	"OR-A01", "OR-A03", "OR-A07", "OR-A11", "OR-D01",
	"OR-B01", "OR-B02", "OR-B03", "OR-B04",
}

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

		urls = append(urls, recallProbe(t, srv.URL, ep))
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

// recallProbe builds a usable probe URL for an endpoint. The opaque
// destination endpoints only reveal anything when handed a valid envelope, so
// those are built with the lab's own encoders rather than a placeholder.
func recallProbe(t *testing.T, base string, ep lab.Endpoint) string {
	t.Helper()

	switch ep.ID {
	case "OR-B01":
		return clickProbe(t, base)
	case "OR-B02":
		return upnProbe(t, base)
	case "OR-B03":
		return jwtProbe(t, base)
	default:
		return base + catalogProbe(ep)
	}
}

func catalogProbe(ep lab.Endpoint) string {
	if ep.Param == "" {
		return ep.Probe
	}

	return ep.Probe + "?" + ep.Param + "=" + url.QueryEscape("https://"+lab.AllowedHost+"/")
}
