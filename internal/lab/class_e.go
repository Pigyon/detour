package lab

import (
	"net/http"
	"net/url"
	"strings"
)

func registerE(mux *http.ServeMux) {
	mux.HandleFunc("GET /e01", handleE01)
	mux.HandleFunc("GET /e02", handleE02)
	mux.HandleFunc("GET /e03", handleE03)
}

func handleE01(w http.ResponseWriter, r *http.Request) {
	writeJSNav(w, r.URL.Query().Get("url"))
}

func handleE02(w http.ResponseWriter, r *http.Request) {
	writeJSNav(w, r.URL.Query().Get("url"))
}

func handleE03(w http.ResponseWriter, r *http.Request) {
	redirectIf(w, r.URL.Query().Get("url"), allowExactHostAnyScheme)
}

func allowExactHostAnyScheme(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}

	if u.User != nil {
		return false
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}

	return strings.EqualFold(u.Hostname(), AllowedHost)
}
