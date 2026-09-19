package decode

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
)

// Layer kinds. A kind plus its variant names one reversible transform.
const (
	KindBase64  = "base64"
	KindBase32  = "base32"
	KindHex     = "hex"
	KindZlib    = "zlib"
	KindGzip    = "gzip"
	KindDeflate = "deflate"
	KindBrotli  = "brotli"
	KindJSON    = "json"
	KindForm    = "form"
	KindJWT     = "jwt"
	KindText    = "text"
)

// maxDecodedBytes caps every decompression so a zip bomb cannot exhaust memory.
const maxDecodedBytes = 1 << 20

// Layer is one reversible transform in a decode chain.
type Layer struct {
	Kind    string `json:"kind"`
	Variant string `json:"variant,omitempty"`
	// Prefix and Suffix hold envelope parts carried verbatim through a
	// re-encode, such as a JWT header and signature.
	Prefix string `json:"-"`
	Suffix string `json:"-"`
}

// Name is the stable wire name recorded on a DecoderChain.
func (l Layer) Name() string {
	if l.Variant == "" {
		return l.Kind
	}

	return l.Kind + ":" + l.Variant
}

// transport is a text-to-bytes codec such as base64 or hex.
type transport struct {
	kind    string
	variant string
	decode  func(string) ([]byte, error)
	encode  func([]byte) string
}

var transports = []transport{
	b64Transport("url", base64.URLEncoding),
	b64Transport("url_raw", base64.RawURLEncoding),
	b64Transport("std", base64.StdEncoding),
	b64Transport("std_raw", base64.RawStdEncoding),
	b32Transport("std", base32.StdEncoding),
	b32Transport("std_raw", base32.StdEncoding.WithPadding(base32.NoPadding)),
	{
		kind:    KindHex,
		variant: "lower",
		decode:  hex.DecodeString,
		encode:  hex.EncodeToString,
	},
	{
		kind:    KindHex,
		variant: "upper",
		decode:  hex.DecodeString,
		encode: func(b []byte) string {
			return strings.ToUpper(hex.EncodeToString(b))
		},
	},
}

func b64Transport(variant string, enc *base64.Encoding) transport {
	return transport{
		kind:    KindBase64,
		variant: variant,
		decode:  enc.DecodeString,
		encode:  enc.EncodeToString,
	}
}

func b32Transport(variant string, enc *base32.Encoding) transport {
	return transport{
		kind:    KindBase32,
		variant: variant,
		decode:  enc.DecodeString,
		encode:  enc.EncodeToString,
	}
}

// decodeTransport returns every transport layer that decodes s and re-encodes
// back to s exactly. The round-trip check is what makes the chain reversible:
// a variant that cannot rebuild the original token is never recorded.
func decodeTransport(s string) []layerResult {
	out := []layerResult{}

	if len(s) < minTransportLen {
		return out
	}

	for _, t := range transports {
		raw, err := t.decode(s)
		if err != nil || len(raw) == 0 {
			continue
		}

		if t.encode(raw) != s {
			continue
		}

		out = append(out, layerResult{
			layer: Layer{Kind: t.kind, Variant: t.variant},
			data:  raw,
		})
	}

	return out
}

func encodeTransport(l Layer, data []byte) (string, error) {
	for _, t := range transports {
		if t.kind == l.Kind && t.variant == l.Variant {
			return t.encode(data), nil
		}
	}

	return "", fmt.Errorf("unknown transport %s", l.Name())
}

// compressor is a bytes-to-bytes codec. Compression is not canonical, so a
// re-encode is semantically equal to the original rather than byte-identical.
type compressor struct {
	kind   string
	decode func([]byte) ([]byte, error)
	encode func([]byte) ([]byte, error)
}

// compressors are ordered cheapest and most self-checking first. Raw deflate
// accepts almost anything, so it is tried last.
var compressors = []compressor{
	{kind: KindGzip, decode: decodeGzip, encode: encodeGzip},
	{kind: KindZlib, decode: decodeZlib, encode: encodeZlib},
	{kind: KindBrotli, decode: decodeBrotli, encode: encodeBrotli},
	{kind: KindDeflate, decode: decodeDeflate, encode: encodeDeflate},
}

func decodeCompression(data []byte) []layerResult {
	out := []layerResult{}

	for _, c := range compressors {
		raw, err := c.decode(data)
		if err != nil || len(raw) == 0 {
			continue
		}

		out = append(out, layerResult{layer: Layer{Kind: c.kind}, data: raw})
	}

	return out
}

func encodeCompression(l Layer, data []byte) ([]byte, error) {
	for _, c := range compressors {
		if c.kind == l.Kind {
			return c.encode(data)
		}
	}

	return nil, fmt.Errorf("unknown compressor %s", l.Kind)
}

func readLimited(r io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxDecodedBytes))
	if err != nil {
		return nil, fmt.Errorf("reading compressed stream: %w", err)
	}

	return raw, nil
}

func decodeGzip(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip header: %w", err)
	}

	defer func() { _ = zr.Close() }()

	return readLimited(zr)
}

func encodeGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		_ = zw.Close()

		return nil, fmt.Errorf("gzip write: %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("gzip close: %w", err)
	}

	return buf.Bytes(), nil
}

func decodeZlib(data []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("zlib header: %w", err)
	}

	defer func() { _ = zr.Close() }()

	return readLimited(zr)
}

func encodeZlib(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		_ = zw.Close()

		return nil, fmt.Errorf("zlib write: %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("zlib close: %w", err)
	}

	return buf.Bytes(), nil
}

func decodeDeflate(data []byte) ([]byte, error) {
	fr := flate.NewReader(bytes.NewReader(data))
	defer func() { _ = fr.Close() }()

	return readLimited(fr)
}

func encodeDeflate(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, fmt.Errorf("deflate writer: %w", err)
	}

	if _, err := fw.Write(data); err != nil {
		_ = fw.Close()

		return nil, fmt.Errorf("deflate write: %w", err)
	}

	if err := fw.Close(); err != nil {
		return nil, fmt.Errorf("deflate close: %w", err)
	}

	return buf.Bytes(), nil
}

func decodeBrotli(data []byte) ([]byte, error) {
	return readLimited(brotli.NewReader(bytes.NewReader(data)))
}

func encodeBrotli(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	bw := brotli.NewWriter(&buf)
	if _, err := bw.Write(data); err != nil {
		_ = bw.Close()

		return nil, fmt.Errorf("brotli write: %w", err)
	}

	if err := bw.Close(); err != nil {
		return nil, fmt.Errorf("brotli close: %w", err)
	}

	return buf.Bytes(), nil
}

// decodeJSON accepts objects and arrays only. A bare scalar is not structured
// state and would make every integer look like an envelope.
func decodeJSON(data []byte) (any, bool) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return nil, false
	}

	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()

	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, false
	}

	if dec.More() {
		return nil, false
	}

	return value, true
}

func encodeJSON(value any) ([]byte, error) {
	var buf bytes.Buffer

	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)

	if err := enc.Encode(value); err != nil {
		return nil, fmt.Errorf("encoding json layer: %w", err)
	}

	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// formKey is what a form field name may look like. Without it, a padded
// base64 token parses as a single form pair and the decode stops one layer too
// early, which the round-trip fuzz test catches immediately.
var formKey = regexp.MustCompile(`^[A-Za-z0-9_.\[\]-]+$`)

// decodeForm accepts a percent-encoded form body. It is deliberately strict:
// every pair needs a plausible key and a non-empty value, so neither a stray
// "a=b" inside prose nor a base64 token's trailing padding is mistaken for
// structured state.
func decodeForm(data []byte) (any, bool) {
	raw := string(data)
	if !strings.Contains(raw, "=") || !utf8.ValidString(raw) {
		return nil, false
	}

	values, err := url.ParseQuery(raw)
	if err != nil || len(values) == 0 {
		return nil, false
	}

	out := map[string]any{}

	for key, list := range values {
		if len(list) != 1 || list[0] == "" || !formKey.MatchString(key) {
			return nil, false
		}

		out[key] = list[0]
	}

	return out, true
}

func encodeForm(value any) ([]byte, error) {
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("form layer expects an object")
	}

	values := url.Values{}

	keys := make([]string, 0, len(obj))
	for key := range obj {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	for _, key := range keys {
		values.Set(key, scalarString(obj[key]))
	}

	return []byte(values.Encode()), nil
}

func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	default:
		return fmt.Sprint(v)
	}
}

// decodeJWT splits a three-part token and returns its claims. The signature is
// carried verbatim so a re-encode keeps the shape a server that never verifies
// it will still accept.
func decodeJWT(data []byte) (Layer, any, bool) {
	parts := strings.Split(string(data), ".")
	if len(parts) != jwtParts {
		return Layer{}, nil, false
	}

	if slices.Contains(parts[:2], "") {
		return Layer{}, nil, false
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Layer{}, nil, false
	}

	if _, ok := decodeJSON(header); !ok {
		return Layer{}, nil, false
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Layer{}, nil, false
	}

	claims, ok := decodeJSON(payload)
	if !ok {
		return Layer{}, nil, false
	}

	return Layer{Kind: KindJWT, Prefix: parts[0], Suffix: parts[2]}, claims, true
}

func encodeJWT(l Layer, value any) ([]byte, error) {
	claims, err := encodeJSON(value)
	if err != nil {
		return nil, err
	}

	token := l.Prefix + "." + base64.RawURLEncoding.EncodeToString(claims) + "." + l.Suffix

	return []byte(token), nil
}
