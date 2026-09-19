package decode_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nedlir/detour/internal/decode"
	"github.com/nedlir/detour/internal/lab"
	"github.com/nedlir/detour/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildMatrixOnClickEnvelope is the analysis that makes a report credible
// rather than a guess: the lab click wrapper checks its host and campaign id
// and ignores the 32-hex integrity field entirely.
func TestBuildMatrixOnClickEnvelope(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	blob, err := lab.EncodeClick("https://" + lab.AllowedHost + "/home")
	require.NoError(t, err)

	source := srv.URL + "/track/click2/" + blob + ".html"

	blobs, err := decode.Find(source)
	require.NoError(t, err)
	require.Len(t, blobs, 1)

	matrix, err := decode.BuildMatrix(context.Background(), blobs[0], source, &labReplayer{})
	require.NoError(t, err)

	assert.Equal(t, http.StatusFound, matrix.Baseline.Status)
	assert.Contains(t, matrix.Validated(), model.FieldPath("$[12]"), "host is enforced")
	assert.Contains(t, matrix.Validated(), model.FieldPath("$[15]"), "campaign id is enforced")
	assert.Contains(t, matrix.Ignored(), model.FieldPath("$[10]"), "the integrity field is decorative")

	for _, probe := range matrix.Probes {
		if probe.Path == "$[4]" {
			assert.True(t, probe.Destination, "the destination is measured, never flipped")
			assert.False(t, probe.Validated)
		}
	}
}

func TestBuildMatrixNeedsReplayer(t *testing.T) {
	t.Parallel()

	blob, err := lab.EncodeClick("https://" + lab.AllowedHost + "/home")
	require.NoError(t, err)

	blobs, err := decode.Find("https://trace.lab/track/click2/" + blob)
	require.NoError(t, err)
	require.Len(t, blobs, 1)

	_, err = decode.BuildMatrix(context.Background(), blobs[0], "https://trace.lab/x", nil)
	require.Error(t, err)
}

func TestBuildMatrixRecordsProbeErrors(t *testing.T) {
	t.Parallel()

	blob, err := lab.EncodeUPN("https://example.com/welcome")
	require.NoError(t, err)

	source := "https://esp.lab/ls/click?upn=" + blob

	blobs, err := decode.Find(source)
	require.NoError(t, err)
	require.Len(t, blobs, 1)

	matrix, err := decode.BuildMatrix(context.Background(), blobs[0], source, &failAfterBaseline{})
	require.NoError(t, err)
	require.NotEmpty(t, matrix.Probes)

	errored := 0

	for _, probe := range matrix.Probes {
		if probe.Error != "" {
			errored++

			assert.False(t, probe.Validated)
		}
	}

	assert.Positive(t, errored, "a failed replay is recorded, not silently validated")
	assert.NotContains(t, matrix.Ignored(), model.FieldPath("$.mid"))
}

// labReplayer speaks to the lab over plain net/http. The matrix never follows
// a redirect, so the Location header is the whole answer.
type labReplayer struct{}

func (r *labReplayer) Replay(ctx context.Context, rawURL string) (decode.Outcome, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return decode.Outcome{}, err
	}

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return decode.Outcome{}, err
	}

	defer func() { _ = resp.Body.Close() }()

	return decode.Outcome{Status: resp.StatusCode, Location: resp.Header.Get("Location")}, nil
}

// failAfterBaseline answers the baseline and then refuses, so the matrix has
// to record the failure on each probe.
type failAfterBaseline struct {
	seen bool
}

func (f *failAfterBaseline) Replay(_ context.Context, _ string) (decode.Outcome, error) {
	if !f.seen {
		f.seen = true

		return decode.Outcome{Status: http.StatusFound, Location: "https://example.com/welcome"}, nil
	}

	return decode.Outcome{}, errors.New("replay refused")
}
