package decode

import (
	"context"
	"errors"

	"github.com/nedlir/detour/internal/model"
)

// Outcome is what one replay of an envelope produced.
type Outcome struct {
	Status   int    `json:"status"`
	Location string `json:"location,omitempty"`
}

// Replayer issues one replayed request. The attack engine and detour decode
// supply their own, so the matrix never owns an HTTP client.
type Replayer interface {
	Replay(ctx context.Context, rawURL string) (Outcome, error)
}

// FieldProbe is one envelope field flipped on its own.
type FieldProbe struct {
	Path model.FieldPath `json:"path"`
	// Destination marks the field that carries the navigation target.
	Destination bool `json:"destination"`
	// Validated means the server's answer changed when this field changed.
	Validated bool    `json:"validated"`
	Outcome   Outcome `json:"outcome"`
	Error     string  `json:"error,omitempty"`
}

// Matrix records which fields of an envelope the server actually checks. It is
// what turns a report from a guess into a demonstration: on the KuCoin trace
// wrapper it showed campaign id and host were validated while the 32-hex
// integrity field was ignored entirely.
type Matrix struct {
	Baseline Outcome      `json:"baseline"`
	Probes   []FieldProbe `json:"probes"`
}

// Validated lists the paths the server rejected when flipped.
func (m Matrix) Validated() []model.FieldPath {
	out := []model.FieldPath{}

	for _, p := range m.Probes {
		if p.Validated {
			out = append(out, p.Path)
		}
	}

	return out
}

// Ignored lists the paths the server accepted unchanged, the integrity fields
// that are decorative rather than enforced.
func (m Matrix) Ignored() []model.FieldPath {
	out := []model.FieldPath{}

	for _, p := range m.Probes {
		if !p.Validated && p.Error == "" {
			out = append(out, p.Path)
		}
	}

	return out
}

// BuildMatrix flips every field of the envelope one at a time and records what
// the server checks. destinations are excluded from the flip, since changing
// them is the attack rather than the measurement.
func BuildMatrix(ctx context.Context, b Blob, base string, r Replayer) (Matrix, error) {
	if r == nil {
		return Matrix{}, errors.New("decode: nil replayer")
	}

	original, err := b.rebuild(base, clone(b.Chain.Value))
	if err != nil {
		return Matrix{}, err
	}

	baseline, err := r.Replay(ctx, original)
	if err != nil {
		return Matrix{}, err
	}

	matrix := Matrix{Baseline: baseline, Probes: []FieldProbe{}}
	destinations := destinationPaths(b.Fields)

	for _, leaf := range leaves(b.Chain.Value) {
		probe := FieldProbe{Path: leaf.Path}
		if _, ok := destinations[leaf.Path]; ok {
			probe.Destination = true
			matrix.Probes = append(matrix.Probes, probe)

			continue
		}

		matrix.Probes = append(matrix.Probes, probeField(ctx, b, base, leaf, baseline, r, probe))
	}

	return matrix, nil
}

func probeField(
	ctx context.Context,
	b Blob,
	base string,
	leaf URLField,
	baseline Outcome,
	r Replayer,
	probe FieldProbe,
) FieldProbe {
	current, err := valueAt(b.Chain.Value, leaf.steps)
	if err != nil {
		probe.Error = err.Error()

		return probe
	}

	mutated, err := b.ReplaceField(base, leaf, flip(current))
	if err != nil {
		probe.Error = err.Error()

		return probe
	}

	outcome, err := r.Replay(ctx, mutated)
	if err != nil {
		probe.Error = err.Error()

		return probe
	}

	probe.Outcome = outcome
	probe.Validated = outcome != baseline

	return probe
}

func destinationPaths(fields []URLField) map[model.FieldPath]struct{} {
	out := make(map[model.FieldPath]struct{}, len(fields))
	for _, f := range fields {
		out[f.Path] = struct{}{}
	}

	return out
}

func valueAt(value any, steps []step) (any, error) {
	current := value

	for _, s := range steps {
		next, err := childAt(current, s)
		if err != nil {
			return nil, err
		}

		current = next
	}

	return current, nil
}
