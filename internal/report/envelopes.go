package report

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/nedlir/detour/internal/decode"
)

// fileEnvelopes is where opaque envelopes that resisted every automatic
// bypass are written, so a human reviewing the run has the full decoded
// breakdown in hand instead of having to rerun detour decode by hand on
// each one.
const fileEnvelopes = "opaque_envelopes.json"

// EnvelopeReport is one opaque envelope's decoded breakdown: what it is made
// of, not whether a bypass was found. The engine already tried and did not
// find one, or the source would not be here at all.
type EnvelopeReport struct {
	Source string            `json:"source"`
	Token  string            `json:"token"`
	Layers []string          `json:"layers"`
	Value  any               `json:"value"`
	Fields []decode.URLField `json:"url_fields"`
}

// WriteOpaqueEnvelopes writes the decoded breakdown of every source in urls.
// An empty urls writes nothing: a file that says "no opaque envelopes" looks
// identical to one that was never written by a target that never produced
// Coverage.OpaqueEnvelopes at all, and the distinction is not worth a file.
func WriteOpaqueEnvelopes(dir string, urls []string) error {
	if len(urls) == 0 {
		return nil
	}

	out := make([]EnvelopeReport, 0, len(urls))

	for _, u := range urls {
		blobs, err := decode.Find(u)
		if err != nil {
			continue
		}

		for _, b := range blobs {
			out = append(out, EnvelopeReport{
				Source: u,
				Token:  b.Token,
				Layers: layerNames(b.Chain),
				Value:  b.Chain.Value,
				Fields: b.Fields,
			})
		}
	}

	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding opaque envelopes: %w", err)
	}

	raw = append(raw, '\n')

	return writeFile(filepath.Join(dir, fileEnvelopes), raw)
}

func layerNames(chain *decode.Chain) []string {
	if chain == nil {
		return nil
	}

	out := make([]string, 0, len(chain.Layers))
	for _, l := range chain.Layers {
		out = append(out, l.Name())
	}

	return out
}
