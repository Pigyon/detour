package decode

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/nedlir/detour/internal/model"
)

const (
	// maxDepth caps how many transforms a chain may stack. Real envelopes sit
	// at two or three; anything deeper is a decoder loop, not a destination.
	maxDepth = 8
	// minTransportLen is the shortest token worth decoding as base64 or hex.
	minTransportLen = 8
	jwtParts        = 3
	// maxNodes bounds the backtracking search. Raw deflate accepts almost any
	// input, so an unbounded walk over hostile bytes would fan out forever.
	maxNodes = 512
)

// ErrNotStructured means no layer combination reached structured state.
var ErrNotStructured = errors.New("decode: token is not structured state")

// Chain is a decoded opaque token: the exact transforms that opened it, and
// the structure they revealed. Encode walks the transforms in reverse.
type Chain struct {
	Layers []Layer `json:"layers"`
	Value  any     `json:"value"`
}

type layerResult struct {
	layer Layer
	data  []byte
}

// Decode opens token and requires the result to hold a navigation destination.
// This is the engine's entry point: a structure with no URL in it is not a
// candidate, however cleanly it decoded.
func Decode(token string) (*Chain, error) {
	return decodeWith(token, hasURLField)
}

// Envelope opens token and accepts any structured state, with or without a
// URL inside. detour decode uses it so an operator can see what an envelope
// holds even when detour would not attack it.
func Envelope(token string) (*Chain, error) {
	return decodeWith(token, func(any) bool { return true })
}

func decodeWith(token string, accept func(any) bool) (*Chain, error) {
	if token == "" {
		return nil, ErrNotStructured
	}

	budget := maxNodes

	chain, ok := search([]byte(token), 0, accept, &budget)
	if !ok {
		return nil, ErrNotStructured
	}

	return chain, nil
}

// search is a depth-first walk over the possible transform stacks. It
// backtracks, so a tempting but wrong layer (raw deflate accepts nearly any
// input) cannot strand the decode on a dead branch.
//
// Order matters. The strict terminals run first because JSON and a JWT are
// unambiguous. The loose ones run last, after every transform has been tried,
// because a padded base64 token parses as a one-pair form and would otherwise
// end the chain a layer early.
func search(data []byte, depth int, accept func(any) bool, budget *int) (*Chain, bool) {
	if depth > maxDepth || len(data) == 0 || *budget <= 0 {
		return nil, false
	}

	*budget--

	if chain, ok := strictTerminal(data, accept); ok {
		return chain, true
	}

	for _, next := range decodeCompression(data) {
		if chain, ok := search(next.data, depth+1, accept, budget); ok {
			return prepend(next.layer, chain), true
		}
	}

	if !utf8.Valid(data) {
		return nil, false
	}

	for _, next := range decodeTransport(string(data)) {
		if chain, ok := search(next.data, depth+1, accept, budget); ok {
			return prepend(next.layer, chain), true
		}
	}

	return looseTerminal(data, accept)
}

// strictTerminal ends a chain on a structure that could not be anything else.
func strictTerminal(data []byte, accept func(any) bool) (*Chain, bool) {
	if layer, claims, ok := decodeJWT(data); ok && accept(claims) {
		return &Chain{Layers: []Layer{layer}, Value: claims}, true
	}

	if value, ok := decodeJSON(data); ok && accept(value) {
		return &Chain{Layers: []Layer{{Kind: KindJSON}}, Value: value}, true
	}

	return nil, false
}

// looseTerminal ends a chain on a shape that plain text can imitate.
func looseTerminal(data []byte, accept func(any) bool) (*Chain, bool) {
	if value, ok := decodeForm(data); ok && accept(value) {
		return &Chain{Layers: []Layer{{Kind: KindForm}}, Value: value}, true
	}

	if text, ok := decodeText(data); ok && accept(text) {
		return &Chain{Layers: []Layer{{Kind: KindText}}, Value: text}, true
	}

	return nil, false
}

// decodeText is the terminal for a bare encoded destination: a token whose
// only content is the URL itself.
func decodeText(data []byte) (string, bool) {
	s := string(data)
	if !utf8.ValidString(s) || !looksLikeURL(s) {
		return "", false
	}

	return s, true
}

func prepend(l Layer, chain *Chain) *Chain {
	chain.Layers = append([]Layer{l}, chain.Layers...)

	return chain
}

// Encode rebuilds a token from value by walking the chain's layers in reverse.
func (c *Chain) Encode(value any) (string, error) {
	if c == nil || len(c.Layers) == 0 {
		return "", errors.New("decode: empty chain")
	}

	last := len(c.Layers) - 1

	data, err := encodeStructural(c.Layers[last], value)
	if err != nil {
		return "", err
	}

	for i := last - 1; i >= 0; i-- {
		layer := c.Layers[i]

		data, err = encodeLayer(layer, data)
		if err != nil {
			return "", err
		}
	}

	return string(data), nil
}

func encodeLayer(l Layer, data []byte) ([]byte, error) {
	switch l.Kind {
	case KindBase64, KindBase32, KindHex:
		encoded, err := encodeTransport(l, data)
		if err != nil {
			return nil, err
		}

		return []byte(encoded), nil
	case KindZlib, KindGzip, KindDeflate, KindBrotli:
		return encodeCompression(l, data)
	default:
		return nil, fmt.Errorf("decode: layer %s is not a transform", l.Name())
	}
}

func encodeStructural(l Layer, value any) ([]byte, error) {
	switch l.Kind {
	case KindJSON:
		return encodeJSON(value)
	case KindForm:
		return encodeForm(value)
	case KindJWT:
		return encodeJWT(l, value)
	case KindText:
		s, ok := value.(string)
		if !ok {
			return nil, errors.New("decode: text layer expects a string")
		}

		return []byte(s), nil
	default:
		return nil, fmt.Errorf("decode: layer %s does not end a chain", l.Name())
	}
}

// Decoders projects the chain onto the model's DecoderChain.
func (c *Chain) Decoders() []model.Decoder {
	if c == nil {
		return []model.Decoder{}
	}

	out := make([]model.Decoder, 0, len(c.Layers))
	for _, l := range c.Layers {
		out = append(out, model.Decoder{Kind: l.Name()})
	}

	return out
}

// TechniqueID names the REFERENCE.md class this envelope belongs to: a JWT
// carrying the destination (OR-B03), a compressed click wrapper (OR-B01), or
// a plain unsigned wrapper (OR-B02).
func (c *Chain) TechniqueID() string {
	if c == nil {
		return "OR-B02"
	}

	for _, l := range c.Layers {
		if l.Kind == KindJWT {
			return "OR-B03"
		}
	}

	for _, l := range c.Layers {
		switch l.Kind {
		case KindZlib, KindGzip, KindDeflate, KindBrotli:
			return "OR-B01"
		}
	}

	return "OR-B02"
}
