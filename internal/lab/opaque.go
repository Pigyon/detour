package lab

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const clickFieldCount = 17

// ClickEnvelope is the decoded EngageLab-style tracking blob.
type ClickEnvelope struct {
	Dest      string
	Host      string
	Campaign  int
	Integrity string
}

// registerOpaqueDestinations mounts encoded and opaque destination fixtures
// (OR-B01 through OR-B05): click blobs, unsigned wrappers, JWT claims,
// double-decode, and nested hops.
func registerOpaqueDestinations(mux *http.ServeMux) {
	mux.HandleFunc("GET /track/click2/{blob}", handleClick)
	mux.HandleFunc("GET /ls/click", handleUPN)
	mux.HandleFunc("GET /b03", handleJWT)
	mux.HandleFunc("GET /b04", handleDoubleDecode)
	mux.HandleFunc("GET /b05", handleChainOuter)
	mux.HandleFunc("GET /b05/inner", handleChainInner)
}

func handleClick(w http.ResponseWriter, r *http.Request) {
	blob := r.PathValue("blob")

	env, err := DecodeClick(blob)
	if err != nil {
		reject(w, "invalid blob")

		return
	}

	if env.Host != clickHost || env.Campaign != clickCampaign {
		reject(w, "envelope rejected")

		return
	}

	found(w, env.Dest)
}

// EncodeClick builds a valid lab tracking blob for dest.
func EncodeClick(dest string) (string, error) {
	env := []any{
		788792,
		"",
		"0000000000000_106519_0_0.sc-0_0_0_0-inbound0$poc@example.com",
		0,
		url.QueryEscape(dest),
		0,
		"false",
		"127.0.0.1",
		"",
		"",
		"00000000000000000000000000000000",
		"",
		clickHost,
		map[string]any{},
		map[string]any{"messageId": "00000000-0000-0000-0000-000000000000"},
		clickCampaign,
		165,
	}

	raw, err := json.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("marshaling click envelope: %w", err)
	}

	var buf bytes.Buffer

	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		_ = zw.Close()

		return "", fmt.Errorf("compressing click envelope: %w", err)
	}

	if err := zw.Close(); err != nil {
		return "", fmt.Errorf("closing zlib writer: %w", err)
	}

	return base64.URLEncoding.EncodeToString(buf.Bytes()), nil
}

// DecodeClick expands a tracking blob. The integrity field is ignored on
// purpose: that is the B01 bug.
func DecodeClick(blob string) (ClickEnvelope, error) {
	blob = strings.TrimSuffix(blob, ".html")

	raw, err := decodeBlobBytes(blob)
	if err != nil {
		return ClickEnvelope{}, err
	}

	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return ClickEnvelope{}, fmt.Errorf("zlib: %w", err)
	}

	defer func() { _ = zr.Close() }()

	limited, err := io.ReadAll(io.LimitReader(zr, maxBlobBytes))
	if err != nil {
		return ClickEnvelope{}, fmt.Errorf("reading zlib: %w", err)
	}

	var fields []any
	if err := json.Unmarshal(limited, &fields); err != nil {
		return ClickEnvelope{}, fmt.Errorf("json: %w", err)
	}

	if len(fields) < clickFieldCount {
		return ClickEnvelope{}, fmt.Errorf("envelope length %d", len(fields))
	}

	dest, _ := fields[4].(string)
	if unesc, err := url.QueryUnescape(dest); err == nil {
		dest = unesc
	}

	host, _ := fields[12].(string)
	integrity, _ := fields[10].(string)
	campaign := asInt(fields[15])

	return ClickEnvelope{
		Dest:      dest,
		Host:      host,
		Campaign:  campaign,
		Integrity: integrity,
	}, nil
}

func decodeBlobBytes(blob string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.URLEncoding,
		base64.RawURLEncoding,
		base64.StdEncoding,
		base64.RawStdEncoding,
	}

	for _, enc := range encodings {
		raw, err := enc.DecodeString(blob)
		if err == nil && len(raw) > 0 {
			return raw, nil
		}
	}

	return nil, errors.New("base64: no encoding accepted the blob")
}

func asInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()

		return int(i)
	case int:
		return n
	default:
		return 0
	}
}

func handleUPN(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("upn")
	if raw == "" {
		reject(w, "missing upn")

		return
	}

	payload, err := decodeBlobBytes(raw)
	if err != nil {
		reject(w, "invalid upn")

		return
	}

	var obj map[string]any
	if err := json.Unmarshal(payload, &obj); err != nil {
		reject(w, "invalid upn json")

		return
	}

	dest, _ := obj["url"].(string)
	if dest == "" {
		dest, _ = obj["dest"].(string)
	}

	if dest == "" {
		reject(w, "no destination")

		return
	}

	found(w, dest)
}

func handleJWT(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	parts := strings.Split(token, ".")

	if len(parts) < 2 {
		reject(w, "invalid token")

		return
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			reject(w, "invalid token payload")

			return
		}
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		reject(w, "invalid claims")

		return
	}

	dest := firstString(claims, "redirect", "rurl", "dest")
	if dest == "" {
		reject(w, "no destination claim")

		return
	}

	found(w, dest)
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}

	return ""
}

func handleDoubleDecode(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("next")
	if raw == "" || strings.Contains(raw, "://") {
		reject(w, "absolute after one decode")

		return
	}

	dest, err := url.QueryUnescape(raw)
	if err != nil || dest == "" {
		reject(w, "invalid next")

		return
	}

	found(w, dest)
}

func handleChainOuter(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")

	u, err := url.Parse(raw)
	if err != nil || raw == "" {
		reject(w, "rejected")

		return
	}

	sameHost := u.Host == "" || u.Hostname() == requestHost(r) || u.Host == r.Host
	inner := strings.HasPrefix(u.Path, "/b05/inner")

	if !sameHost || !inner {
		reject(w, "not on allowlist")

		return
	}

	found(w, raw)
}

func handleChainInner(w http.ResponseWriter, r *http.Request) {
	redirectIf(w, r.URL.Query().Get("url"), func(raw string) bool {
		return raw != ""
	})
}
