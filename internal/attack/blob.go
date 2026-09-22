package attack

import (
	"context"
	"net/url"

	"github.com/nedlir/detour/internal/decode"
	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/payload"
)

// attackBlobs probes destinations that are not parameters at all: a
// high-entropy path segment or value that decodes to structured state with a
// URL buried in it. The envelope is rebuilt through the exact inverse of the
// decode chain, so only the destination field changes.
func (e *Engine) attackBlobs(ctx context.Context, raw string) ([]model.Finding, error) {
	// attackOne has already parsed raw, so a failure here is a real one.
	blobs, err := decode.Find(raw)
	if err != nil {
		return nil, err
	}

	hits := []model.Finding{}

	for _, b := range blobs {
		for _, field := range b.Fields {
			f, ok, err := e.attackBlobField(ctx, raw, b, field)
			if err != nil {
				return nil, err
			}

			if ok {
				hits = append(hits, f)
			}
		}
	}

	return hits, nil
}

// attackBlobField walks the payloads against one destination field and stops
// at the first hit. Once an envelope is shown not to authenticate its
// destination, further payloads only add duplicate findings.
func (e *Engine) attackBlobField(
	ctx context.Context,
	raw string,
	b decode.Blob,
	field decode.URLField,
) (model.Finding, bool, error) {
	ctxBlob := blobContextFor(b, field)
	trusted := hostOfField(field, raw)

	for _, p := range e.payloads {
		if p.Mechanism != mechQuery {
			continue
		}

		expanded := payload.Expand(p, e.canary, trusted, field.Value)

		probed, err := b.Replace(raw, field, expanded)
		if err != nil {
			continue
		}

		alt := payload.Expand(p, AltCanary(e.canary), trusted, field.Value)

		altProbed, err := b.Replace(raw, field, alt)
		if err != nil {
			continue
		}

		f, ok, err := e.confirm(ctx, probe{
			source:    raw,
			probed:    probed,
			altProbed: altProbed,
			expanded:  expanded,
			payload:   p,
			param:     b.Site.ParamName,
			blob:      ctxBlob,
		})
		if err != nil {
			return model.Finding{}, false, err
		}

		if ok {
			return f, true, nil
		}
	}

	return model.Finding{}, false, nil
}

func blobContextFor(b decode.Blob, field decode.URLField) *blobContext {
	fields := make([]model.FieldPath, 0, len(b.Fields))
	for _, f := range b.Fields {
		fields = append(fields, f.Path)
	}

	return &blobContext{
		technique: b.Chain.TechniqueID(),
		chain:     b.Chain.Decoders(),
		fields:    fields,
		field:     field.Path,
	}
}

// hostOfField is the host a payload template should pose as: the envelope's
// own current destination, falling back to the source host.
func hostOfField(field decode.URLField, raw string) string {
	if u, err := url.Parse(field.Value); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}

	return hostOf(raw)
}
