package attack_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/nedlir/detour/internal/attack"
	"github.com/nedlir/detour/internal/lab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recallIDs are the techniques the server-side engine reaches without a
// browser. Everything the engine can produce belongs here: an id that drops
// out of this list is a regression nobody notices otherwise.
//
// OR-A15 is absent because detour reads it off destinations it already has
// rather than probing for it: probing means handing a target an internal
// address, which is the operator's call and never a scanner's.
//
// The client-side ids (OR-C01 to OR-C03, OR-E01 to OR-E03, OR-F09) are absent
// on purpose. Their lab fixtures answer 200 with a script, so no Location
// exists for this stage to read, and the js and confirm gates cover them.
//
// The engine still labels those schemes when a server reflects one into a
// Location, which is a different endpoint shape than the lab models here.
var recallIDs = []string{
	"OR-A01", "OR-A02", "OR-A03", "OR-A04", "OR-A07", "OR-A11", "OR-A16",
	"OR-B01", "OR-B02", "OR-B03", "OR-B04", "OR-B05",
	"OR-D01", "OR-D02", "OR-D03", "OR-D04", "OR-F01", "OR-F07",
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
		if !covers(ep, want) {
			continue
		}

		urls = append(urls, recallProbe(t, srv.URL, ep))
	}

	// The chained class needs to know about a same-host redirector, which a
	// full run gets from selection.
	eng.SetChainTargets([]attack.ChainTarget{
		{Path: "/b05/inner", Param: paramURL},
		{Path: "/f07/r1"},
	})

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

// covers reports whether an endpoint is the fixture for any wanted id, either
// as its own id or as one it declares it covers.
func covers(ep lab.Endpoint, want map[string]struct{}) bool {
	if _, ok := want[ep.ID]; ok {
		return true
	}

	for _, id := range ep.Covers {
		if _, ok := want[id]; ok {
			return true
		}
	}

	return false
}

// recallProbe builds a usable probe URL for an endpoint. The catalog now
// carries real envelopes and real registered values, so there is nothing left
// to special case here.
func recallProbe(t *testing.T, base string, ep lab.Endpoint) string {
	t.Helper()

	return base + catalogProbe(ep)
}

func catalogProbe(ep lab.Endpoint) string {
	// A probe the catalog already built in full (an envelope, say) carries its
	// own parameter and must not have a second one bolted on.
	if ep.Param == "" || strings.Contains(ep.Probe, "?") {
		return ep.Probe
	}

	// Some endpoints only do anything for one particular value, and the
	// catalog now states it rather than leaving every caller to guess.
	value := ep.ProbeValue
	if value == "" {
		value = "https://" + lab.AllowedHost + "/"
	}

	return ep.Probe + "?" + ep.Param + "=" + url.QueryEscape(value)
}

// TestLabAllowlistBypassFromARealisticSeed uses the seed an archive actually
// returns, rather than the answer.
//
// The recall gate above hands every probe `https://<allowed host>/`, which is
// what a validator trusts. A harvested URL essentially never does, and while
// the engine guessed the trusted host from the seed alone, that difference was
// the whole allowlist-bypass family silently finding nothing. The gate could
// not see it because the gate was supplying the answer.
func TestLabAllowlistBypassFromARealisticSeed(t *testing.T) {
	t.Parallel()

	eng, srv := newEngine(t)

	probe := srv.URL + "/a01?url=" + url.QueryEscape("/account")

	bare, err := eng.Run(context.Background(), []string{probe})
	require.NoError(t, err)
	assert.Empty(t, bare, "nothing in that seed names the trusted host")

	// The js stage reads the allowlist out of the page's guards, and a
	// pipeline run hands it to the engine.
	eng.SetTrustedHosts([]string{lab.AllowedHost})

	found, err := eng.Run(context.Background(), []string{probe})
	require.NoError(t, err)

	_, ok := findingByTechnique(found, "OR-A01")
	assert.True(t, ok, "the trusted host makes the same endpoint reachable")
}
