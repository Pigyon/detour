package lab

import (
	"net/http"
	"net/url"
	"strings"
)

// registerParserDifferentials mounts parser-differential fixtures (OR-A01
// through OR-A15). Each route models a validate-then-use gap between an
// allowlist and the Location sink.
func registerParserDifferentials(mux *http.ServeMux) {
	mux.HandleFunc("GET /a01", paramRedirect("url", allowA01))
	mux.HandleFunc("GET /a02", paramRedirect("url", allowA02))
	mux.HandleFunc("GET /a03", paramRedirect("url", allowA03))
	mux.HandleFunc("GET /a04", paramRedirect("url", allowA04))
	mux.HandleFunc("GET /a05", paramRedirect("url", allowA05))
	mux.HandleFunc("GET /a06", paramRedirect("url", allowA06))
	mux.HandleFunc("GET /a07", paramRedirect("url", allowA07))
	mux.HandleFunc("GET /a08", paramRedirect("url", allowA08))
	mux.HandleFunc("GET /a09", paramRedirect("url", allowA09))
	mux.HandleFunc("GET /a10", paramRedirect("redirect_uri", allowA10))
	mux.HandleFunc("GET /a12", paramRedirect("url", allowA12))
	mux.HandleFunc("GET /a13", paramRedirect("url", allowA13))
	mux.HandleFunc("GET /a14", paramRedirect("url", allowA14))
	mux.HandleFunc("GET /a15", paramRedirect("url", allowA15))
}

func allowA01(raw string) bool {
	return strings.HasPrefix(raw, "http://"+AllowedHost) || strings.HasPrefix(raw, "https://"+AllowedHost)
}

func allowA02(raw string) bool {
	if !strings.Contains(raw, AllowedHost) {
		return false
	}

	plainUserinfo := strings.Count(raw, "@") == 1 &&
		!strings.Contains(raw, ":@") &&
		!strings.Contains(raw, " &@")

	return !plainUserinfo
}

func allowA03(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}

	return u.Host == ""
}

func allowA04(raw string) bool {
	host := springLikeHost(raw)

	return host == AllowedHost || host == AllowedHost+":443"
}

func springLikeHost(raw string) string {
	rest := raw
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}

	if i := strings.Index(rest, "[@"); i >= 0 {
		rest = rest[i+2:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			rest = rest[:j]
		}

		return rest
	}

	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}

	return u.Hostname()
}

func allowA05(raw string) bool {
	if strings.Contains(raw, AllowedHost+"\u3002") ||
		strings.Contains(raw, AllowedHost+"%E3%80%82") ||
		strings.Contains(raw, "\uFF0F") ||
		strings.Contains(raw, "\uFF3C") {
		return strings.Contains(raw, AllowedHost)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return false
	}

	return u.Hostname() == AllowedHost
}

func allowA06(raw string) bool {
	if strings.HasPrefix(raw, "//") ||
		strings.HasPrefix(raw, "http://") ||
		strings.HasPrefix(raw, "https://") {
		return false
	}

	return raw != ""
}

func allowA07(raw string) bool {
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return false
	}

	return raw != ""
}

func allowA08(raw string) bool {
	return strings.Contains(raw, AllowedHost)
}

func allowA09(raw string) bool {
	return strings.HasPrefix(hostToken(raw), AllowedHost)
}

func allowA10(raw string) bool {
	return strings.HasPrefix(raw, "https://"+AllowedHost+"/app/")
}

func handleA11(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/a11/")
	if rest == r.URL.Path {
		rest = strings.TrimPrefix(r.URL.Path, "/a11")
		rest = strings.TrimPrefix(rest, "/")
	}

	w.Header().Set("Location", "/safe")

	if loc, ok := injectedLocation(rest); ok {
		w.Header().Add("Location", loc)
	}

	w.WriteHeader(http.StatusFound)
}

func injectedLocation(raw string) (string, bool) {
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		decoded = raw
	}

	const marker = "\r\nLocation:"

	i := strings.Index(decoded, marker)
	if i < 0 {
		i = strings.Index(decoded, "\nLocation:")
		if i < 0 {
			return "", false
		}

		rest := strings.TrimSpace(decoded[i+len("\nLocation:"):])
		rest = firstLine(rest)

		return rest, rest != ""
	}

	rest := strings.TrimSpace(decoded[i+len(marker):])
	rest = firstLine(rest)

	return rest, rest != ""
}

func firstLine(s string) string {
	s = strings.Split(s, "\r")[0]

	return strings.Split(s, "\n")[0]
}

func allowA12(raw string) bool {
	trunc, _, _ := strings.Cut(raw, "\x00")
	trunc, _, _ = strings.Cut(trunc, "%00")

	return strings.Contains(trunc, AllowedHost)
}

func allowA13(raw string) bool {
	return strings.HasSuffix(raw, AllowedHost)
}

func allowA14(raw string) bool {
	if strings.Contains(raw, "http://") || strings.Contains(raw, "https://") {
		return false
	}

	return raw != ""
}

func allowA15(raw string) bool {
	u, ok := parseAbsolute(raw)
	if !ok {
		return false
	}

	switch strings.ToLower(u.Hostname()) {
	case "127.0.0.1", "localhost", "169.254.169.254", "::1":
		return false
	default:
		return true
	}
}
