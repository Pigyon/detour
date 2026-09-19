// Package decode opens opaque navigation state: it recognizes an encoded
// token, decodes it through a reversible chain, locates the destination at any
// depth, mutates only that field, and rebuilds the exact envelope. This is the
// class where the destination is not a parameter at all.
package decode

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/nedlir/detour/internal/model"
)

// Site is where an opaque token sits inside a URL.
type Site struct {
	Representation model.Representation `json:"representation"`
	// ParamName is the query key holding the token, empty for a path segment.
	ParamName string `json:"param_name,omitempty"`
	// SegmentIndex is the token's position in the path, ignored for a query.
	SegmentIndex int `json:"segment_index,omitempty"`
	// Suffix is the cosmetic file extension stripped before decoding.
	Suffix string `json:"suffix,omitempty"`
}

// Blob is one decoded opaque token together with where it came from.
type Blob struct {
	Site   Site       `json:"site"`
	Token  string     `json:"token"`
	Chain  *Chain     `json:"chain"`
	Fields []URLField `json:"url_fields"`
}

// Find returns every opaque token in raw that decodes to structured state with
// a navigation destination inside it.
func Find(raw string) ([]Blob, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing source: %w", err)
	}

	out := []Blob{}
	out = append(out, findInPath(parsed)...)
	out = append(out, findInQuery(parsed)...)

	return out, nil
}

func findInPath(parsed *url.URL) []Blob {
	out := []Blob{}

	for i, segment := range strings.Split(parsed.EscapedPath(), "/") {
		token, err := url.PathUnescape(segment)
		if err != nil {
			continue
		}

		site := Site{Representation: model.RepresentationPathSegment, SegmentIndex: i}

		if blob, ok := open(token, site); ok {
			out = append(out, blob)
		}
	}

	return out
}

func findInQuery(parsed *url.URL) []Blob {
	out := []Blob{}
	query := parsed.Query()

	names := make([]string, 0, len(query))
	for name := range query {
		names = append(names, name)
	}

	sort.Strings(names)

	for _, name := range names {
		for _, value := range query[name] {
			site := Site{Representation: model.RepresentationQueryParameter, ParamName: name}

			if blob, ok := open(value, site); ok {
				out = append(out, blob)

				break
			}
		}
	}

	return out
}

// open decodes one token if it looks opaque, recording the suffix it wore.
func open(token string, site Site) (Blob, bool) {
	stripped, suffix := StripSuffix(token)
	if !IsOpaque(stripped) {
		return Blob{}, false
	}

	chain, err := Decode(stripped)
	if err != nil {
		return Blob{}, false
	}

	site.Suffix = suffix

	return Blob{
		Site:   site,
		Token:  stripped,
		Chain:  chain,
		Fields: URLFields(chain.Value),
	}, true
}

// Replace rebuilds base with the blob's destination field pointing at dest.
// Every other byte of the envelope is preserved.
func (b Blob) Replace(base string, field URLField, dest string) (string, error) {
	value := clone(b.Chain.Value)

	next := dest
	if field.Escaped {
		next = url.QueryEscape(dest)
	}

	if err := setAt(value, field.steps, next); err != nil {
		return "", err
	}

	return b.rebuild(base, value)
}

// ReplaceField rebuilds base with an arbitrary field set to v. The field
// matrix uses it to flip everything that is not the destination.
func (b Blob) ReplaceField(base string, field URLField, v any) (string, error) {
	value := clone(b.Chain.Value)
	if err := setAt(value, field.steps, v); err != nil {
		return "", err
	}

	return b.rebuild(base, value)
}

func (b Blob) rebuild(base string, value any) (string, error) {
	token, err := b.Chain.Encode(value)
	if err != nil {
		return "", err
	}

	return b.Site.Apply(base, token+b.Site.Suffix)
}

// Apply puts token back where the original one sat in base.
func (s Site) Apply(base, token string) (string, error) {
	parsed, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parsing base: %w", err)
	}

	if s.Representation == model.RepresentationQueryParameter {
		query := parsed.Query()
		query.Set(s.ParamName, token)
		parsed.RawQuery = query.Encode()

		return parsed.String(), nil
	}

	segments := strings.Split(parsed.EscapedPath(), "/")
	if s.SegmentIndex < 0 || s.SegmentIndex >= len(segments) {
		return "", fmt.Errorf("segment %d is out of range", s.SegmentIndex)
	}

	segments[s.SegmentIndex] = url.PathEscape(token)
	escaped := strings.Join(segments, "/")

	parsed.RawPath = escaped

	decoded, err := url.PathUnescape(escaped)
	if err != nil {
		parsed.Path = escaped
	} else {
		parsed.Path = decoded
	}

	return parsed.String(), nil
}

// Candidates projects the blobs in raw onto NavigationCandidates so the attack
// engine sees an opaque blob as just another representation.
func Candidates(raw string) ([]model.NavigationCandidate, error) {
	blobs, err := Find(raw)
	if err != nil {
		return nil, err
	}

	out := make([]model.NavigationCandidate, 0, len(blobs))

	for _, b := range blobs {
		cand := model.NewNavigationCandidate(raw, model.RepresentationOpaqueBlob)
		cand.ParamName = b.Site.ParamName
		cand.DecoderChain = b.Chain.Decoders()

		for _, f := range b.Fields {
			cand.URLFields = append(cand.URLFields, f.Path)
		}

		out = append(out, cand)
	}

	return out, nil
}
