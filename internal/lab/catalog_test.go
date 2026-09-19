package lab_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/nedlir/detour/internal/lab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCatalogCoversEveryTechniqueID(t *testing.T) {
	t.Parallel()

	covered := map[string]struct{}{}

	for _, ep := range lab.Catalog() {
		if ep.ID != "" {
			covered[ep.ID] = struct{}{}
		}

		for _, id := range ep.Covers {
			covered[id] = struct{}{}
		}
	}

	for _, id := range lab.TechniqueIDs {
		_, ok := covered[id]
		assert.True(t, ok, "missing coverage for %s", id)
	}

	assert.Len(t, lab.TechniqueIDs, 43)
}

func TestCatalogProbesAreRouted(t *testing.T) {
	t.Parallel()

	srv := newLabServer(t)
	client := noFollow(t, srv)

	for _, ep := range lab.Catalog() {
		t.Run(ep.Path, func(t *testing.T) {
			t.Parallel()

			res := doGet(t, client, srv.URL+ep.Probe)
			assert.NotEqual(t, http.StatusNotFound, res.Status, ep.Path)
		})
	}
}

func TestWriteCatalogJSON(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	require.NoError(t, lab.WriteCatalog(&buf))

	var got []lab.Endpoint
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.GreaterOrEqual(t, len(got), 43)
}

func TestCatalogEndpointJSON(t *testing.T) {
	t.Parallel()

	srv := newLabServer(t)
	client := noFollow(t, srv)
	res := doGet(t, client, srv.URL+"/catalog")
	require.Equal(t, http.StatusOK, res.Status)

	var got []lab.Endpoint
	require.NoError(t, json.Unmarshal([]byte(res.Body), &got))
	assert.NotEmpty(t, got)
}
