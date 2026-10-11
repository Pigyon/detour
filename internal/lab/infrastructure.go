package lab

import (
	"fmt"
	"net/http"
	"strings"
)

// registerInfrastructure mounts fixtures that take no query parameter
// (OR-D01 through OR-D06): forwarded host, destHost, raw path, SAML,
// Referer, and Refresh.
func registerInfrastructure(mux *http.ServeMux) {
	mux.HandleFunc("GET /d01", handleD01)
	mux.HandleFunc("GET /d01/{path...}", handleD01)
	mux.HandleFunc("GET /_next/d02", handleD02)
	mux.HandleFunc("GET /saml/acs", handleSAML)
	mux.HandleFunc("GET /oidc/logout", handleOIDCLogout)
	mux.HandleFunc("GET /adfs/ls", handleWSFed)
	mux.HandleFunc("GET /d05", handleD05)
	mux.HandleFunc("GET /d06", handleD06)
}

func handleD01(w http.ResponseWriter, r *http.Request) {
	host := firstHeader(r, "X-Forwarded-Host", "X-Host", "X-Forwarded-Server")
	if host == "" {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok\n")

		return
	}

	found(w, "https://"+host+r.URL.RequestURI())
}

func firstHeader(r *http.Request, names ...string) string {
	for _, name := range names {
		if v := r.Header.Get(name); v != "" {
			return v
		}
	}

	return ""
}

func handleD02(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("destHost")
	if host == "" {
		reject(w, "missing destHost")

		return
	}

	w.Header().Set("X-Nextjs-Cache", "MISS")
	found(w, "https://"+host+"/")
}

func handleD03(w http.ResponseWriter, r *http.Request) {
	suffix := strings.TrimPrefix(r.URL.Path, "/d03")
	if suffix == "" || suffix == "/" {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok\n")

		return
	}

	moved(w, suffix)
}

func handleSAML(w http.ResponseWriter, r *http.Request) {
	redirectIf(w, r.URL.Query().Get("RelayState"), nonempty)
}

func handleOIDCLogout(w http.ResponseWriter, r *http.Request) {
	redirectIf(w, r.URL.Query().Get("post_logout_redirect_uri"), nonempty)
}

func handleWSFed(w http.ResponseWriter, r *http.Request) {
	redirectIf(w, r.URL.Query().Get("wreply"), nonempty)
}

func handleD05(w http.ResponseWriter, r *http.Request) {
	ref := r.Referer()
	if ref == "" {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok\n")

		return
	}

	found(w, ref)
}

func handleD06(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	if raw == "" {
		reject(w, "missing url")

		return
	}

	w.Header().Set("Refresh", "0;url="+raw)
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "ok\n")
}

func nonempty(raw string) bool {
	return raw != ""
}
