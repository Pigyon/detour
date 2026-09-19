package lab

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
)

func registerC(mux *http.ServeMux) {
	mux.HandleFunc("GET /c01", handleC01)
	mux.HandleFunc("GET /c02", handleC02)
	mux.HandleFunc("GET /c03", handleC03)
	mux.HandleFunc("GET /c03/frame", handleC03Frame)
	mux.HandleFunc("GET /c04", handleC04)
	mux.HandleFunc("GET /auth/back", handleAuthBack)
	mux.HandleFunc("GET /login", handleLogin)
}

func handleC01(w http.ResponseWriter, r *http.Request) {
	writeJSNav(w, r.URL.Query().Get("backUrl"))
}

func handleC02(w http.ResponseWriter, _ *http.Request) {
	writeHTML(w, `<!doctype html><script>location.href=location.hash.slice(1)</script>`+"\n")
}

func handleC03(w http.ResponseWriter, r *http.Request) {
	src := r.URL.Query().Get("src")
	if src == "" {
		src = "/c03/frame?to=https://evil.example/"
	}

	writeHTML(w, fmt.Sprintf(
		`<!doctype html><iframe src="%s"></iframe>`+"\n",
		html.EscapeString(src),
	))
}

func handleC03Frame(w http.ResponseWriter, r *http.Request) {
	payload, err := json.Marshal(r.URL.Query().Get("to"))
	if err != nil {
		http.Error(w, "encode", http.StatusInternalServerError)

		return
	}

	writeHTML(w, "<!doctype html><script>top.location="+string(payload)+"</script>\n")
}

func handleC04(w http.ResponseWriter, r *http.Request) {
	dest := html.EscapeString(r.URL.Query().Get("url"))
	writeHTML(w, fmt.Sprintf(
		`<!doctype html><meta http-equiv="refresh" content="0;url=%s">`+"\n",
		dest,
	))
}

func handleAuthBack(w http.ResponseWriter, r *http.Request) {
	if !hasSession(r) {
		writeHTML(w, "<!doctype html><p>login required</p>\n")

		return
	}

	writeJSNav(w, r.URL.Query().Get("backUrl"))
}

func handleLogin(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: local HTTP lab has no TLS, so Secure cannot be set.
		Name:     SessionCookieName,
		Value:    SessionCookieValue,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	found(w, "/")
}
