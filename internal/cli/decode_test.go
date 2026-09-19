package cli_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/nedlir/detour/internal/cli"
	"github.com/nedlir/detour/internal/lab"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeCommandOpensAClickWrapper(t *testing.T) {
	t.Parallel()

	blob, err := lab.EncodeClick("https://" + lab.AllowedHost + "/home")
	require.NoError(t, err)

	out, errOut := runDecode(t, decodeArgs("https://trace.lab/track/click2/"+blob+".html"))

	report := decodeOutput(t, out)
	require.Len(t, report.Blobs, 1)

	got := report.Blobs[0]
	assert.Equal(t, []string{"base64:url", "zlib", "json"}, got.Layers)
	assert.Equal(t, ".html", got.Site.Suffix)
	require.Len(t, got.Fields, 1)
	assert.Equal(t, "$[4]", got.Fields[0].Path)
	assert.Equal(t, "https://"+lab.AllowedHost+"/home", got.Fields[0].Value)
	assert.Contains(t, got.Mutated, ".html")
	assert.Nil(t, got.Matrix, "the field matrix stays off until it is asked for")
	assert.Contains(t, errOut, "1 opaque blobs")
}

func TestDecodeCommandReportsNothingForAPlainURL(t *testing.T) {
	t.Parallel()

	out, errOut := runDecode(t, decodeArgs("https://site.lab/go?url=https://example.com/"))

	report := decodeOutput(t, out)
	assert.Empty(t, report.Blobs)
	assert.Contains(t, errOut, "0 opaque blobs")
}

func TestDecodeCommandFieldMatrix(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(lab.New().Handler())
	t.Cleanup(srv.Close)

	blob, err := lab.EncodeClick("https://" + lab.AllowedHost + "/home")
	require.NoError(t, err)

	out, _ := runDecode(t, decodeArgs(srv.URL+"/track/click2/"+blob+".html", "--matrix"))

	report := decodeOutput(t, out)
	require.Len(t, report.Blobs, 1)

	matrix := report.Blobs[0].Matrix
	require.NotNil(t, matrix)
	assert.Equal(t, 302, matrix.Baseline.Status)

	validated := map[string]bool{}
	for _, probe := range matrix.Probes {
		validated[probe.Path] = probe.Validated
	}

	assert.True(t, validated["$[12]"], "host is enforced")
	assert.True(t, validated["$[15]"], "campaign id is enforced")
	assert.False(t, validated["$[10]"], "the integrity field is decorative")
}

// decodeReportOutput mirrors the command's JSON so the test reads it as data
// rather than by string matching.
type decodeReportOutput struct {
	Source string `json:"source"`
	Blobs  []struct {
		Site struct {
			Suffix string `json:"suffix"`
		} `json:"site"`
		Layers []string `json:"layers"`
		Fields []struct {
			Path  string `json:"path"`
			Value string `json:"value"`
		} `json:"url_fields"`
		Mutated string `json:"mutated"`
		Matrix  *struct {
			Baseline struct {
				Status int `json:"status"`
			} `json:"baseline"`
			Probes []struct {
				Path      string `json:"path"`
				Validated bool   `json:"validated"`
			} `json:"probes"`
		} `json:"field_matrix"`
	} `json:"blobs"`
}

func runDecode(t *testing.T, args []string) (string, string) {
	t.Helper()

	cmd := cli.NewRoot()
	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)

	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs(args)

	require.NoError(t, cmd.Execute())

	return out.String(), errOut.String()
}

func decodeOutput(t *testing.T, raw string) decodeReportOutput {
	t.Helper()

	var report decodeReportOutput

	require.NoError(t, json.Unmarshal([]byte(raw), &report))

	return report
}

func decodeArgs(extra ...string) []string {
	return append([]string{"--rate", "50", "decode"}, extra...)
}
