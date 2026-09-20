package lab

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func reject(w http.ResponseWriter, msg string) {
	http.Error(w, msg, http.StatusBadRequest)
}

func found(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

func moved(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusMovedPermanently)
}

func redirectIf(w http.ResponseWriter, raw string, allow func(string) bool) {
	if raw == "" || !allow(raw) {
		reject(w, "rejected")

		return
	}

	found(w, raw)
}

func paramRedirect(param string, allow func(string) bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		redirectIf(w, r.URL.Query().Get(param), allow)
	}
}

func writeHTML(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, body)
}

func writeJS(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = fmt.Fprint(w, body)
}

func writeJSNav(w http.ResponseWriter, dest string) {
	payload, err := json.Marshal(dest)
	if err != nil {
		http.Error(w, "encode", http.StatusInternalServerError)

		return
	}

	writeHTML(w, "<!doctype html><script>location.href="+string(payload)+"</script>\n")
}

func hostToken(raw string) string {
	rest := raw
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}

	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}

	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}

	if colon := strings.Index(rest, ":"); colon >= 0 {
		rest = rest[:colon]
	}

	return rest
}

func parseAbsolute(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, false
	}

	return u, true
}

func hasSession(r *http.Request) bool {
	c, err := r.Cookie(SessionCookieName)

	return err == nil && c.Value == SessionCookieValue
}

func requestHost(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		return h
	}

	return r.Host
}
