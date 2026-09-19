package lab

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

var decoyKey = []byte("detour-lab-decoy-hmac-key")

func registerDecoys(mux *http.ServeMux) {
	mux.HandleFunc("GET /decoy/allowlist", handleDecoyAllowlist)
	mux.HandleFunc("GET /decoy/static", handleDecoyStatic)
	mux.HandleFunc("GET /decoy/reflect", handleDecoyReflect)
	mux.HandleFunc("GET /decoy/downgrade", handleDecoyDowngrade)
	mux.HandleFunc("GET /decoy/signed/{blob}", handleDecoySigned)
}

func handleDecoyAllowlist(w http.ResponseWriter, r *http.Request) {
	redirectIf(w, r.URL.Query().Get("backUrl"), allowExactSafe)
}

func allowExactSafe(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}

	if u.User != nil {
		return false
	}

	if u.Scheme != "https" {
		return false
	}

	if strings.EqualFold(u.Scheme, "javascript") {
		return false
	}

	return strings.EqualFold(u.Hostname(), AllowedHost)
}

func handleDecoyStatic(w http.ResponseWriter, _ *http.Request) {
	found(w, "https://"+AllowedHost+"/home")
}

func handleDecoyReflect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintf(w, "saw %s\n", r.URL.Query().Get("url")) //nolint:gosec // G705: text/plain decoy reflection.
}

func handleDecoyDowngrade(w http.ResponseWriter, r *http.Request) {
	redirectIf(w, r.URL.Query().Get("url"), allowExactHostAnyScheme)
}

func handleDecoySigned(w http.ResponseWriter, r *http.Request) {
	dest, err := VerifySignedDest(r.PathValue("blob"))
	if err != nil {
		reject(w, "bad signature")

		return
	}

	found(w, dest)
}

// SignDest returns a HMAC-protected blob for the signed-decoy endpoint.
func SignDest(dest string) string {
	mac := hmac.New(sha256.New, decoyKey)
	_, _ = mac.Write([]byte(dest))
	sum := hex.EncodeToString(mac.Sum(nil))

	return base64.RawURLEncoding.EncodeToString([]byte(dest)) + "." + sum
}

// VerifySignedDest checks the HMAC and returns the destination.
func VerifySignedDest(blob string) (string, error) {
	encoded, sig, ok := strings.Cut(blob, ".")
	if !ok || encoded == "" || sig == "" {
		return "", errors.New("malformed blob")
	}

	dest, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decoding dest: %w", err)
	}

	mac := hmac.New(sha256.New, decoyKey)
	_, _ = mac.Write(dest)
	want := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(want)) {
		return "", errors.New("signature mismatch")
	}

	return string(dest), nil
}
