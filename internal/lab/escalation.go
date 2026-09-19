package lab

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// registerEscalation mounts escalation and vendor-scenario fixtures (OR-F01
// through OR-F10): OAuth nesting, CSP allowlists, SSRF follow, phishing,
// and cache poisoning.
func (l *Lab) registerEscalation(mux *http.ServeMux) {
	mux.HandleFunc("GET /oauth/authorize", handleOAuthAuthorize)
	mux.HandleFunc("GET /csp", handleCSP)
	mux.HandleFunc("GET /csp/redir", paramRedirect("url", nonempty))
	mux.HandleFunc("GET /ssrf/fetch", l.handleSSRF)
	mux.HandleFunc("GET /f04/reset", handleF04)
	mux.HandleFunc("GET /f05", paramRedirect("url", nonempty))
	mux.HandleFunc("GET /login-page", handleLoginPage)
	mux.HandleFunc("GET /f06", handleF06)
	mux.HandleFunc("GET /f07/r1", handleF07R1)
	mux.HandleFunc("GET /f07/r2", handleF07R2)
	mux.HandleFunc("GET /f08", paramRedirect("url", nonempty))
	mux.HandleFunc("GET /f09", handleF09)
	mux.HandleFunc("GET /f10", l.handleF10)
	mux.HandleFunc("GET /landed", handleLanded)
}

func handleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("redirect_uri")
	prefix := "https://" + AllowedHost + "/callback"

	if !strings.HasPrefix(raw, prefix) {
		reject(w, "redirect_uri not registered")

		return
	}

	found(w, raw)
}

func handleCSP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Security-Policy", "script-src https://"+AllowedHost)
	writeHTML(w, "<!doctype html><p>csp</p>\n")
}

func (l *Lab) handleSSRF(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	if raw == "" {
		reject(w, "missing url")

		return
	}

	target, err := url.Parse(raw)
	if err != nil {
		reject(w, "invalid url")

		return
	}

	if target.Host != "" && !sameLabHost(r, target) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, "blocked-off-lab %s\n", target.String()) //nolint:gosec // G705: text/plain fixture, not HTML.

		return
	}

	abs := target
	if abs.Host == "" {
		abs = r.URL.ResolveReference(target)
		abs.Scheme = "http"
		abs.Host = r.Host
	}

	body, loc, err := fetchLab(r.Context(), abs.String(), r.Host)
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)

		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	if loc != "" {
		w.Header().Set("X-Final-URL", loc)
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body) //nolint:gosec // G705: body is fetched only from this lab process.
}

func sameLabHost(r *http.Request, u *url.URL) bool {
	want := requestHost(r)
	got := u.Hostname()

	if got == "" {
		got = hostToken(u.Host)
	}

	if strings.EqualFold(got, want) {
		return true
	}

	return strings.EqualFold(got, "127.0.0.1") && isLoopbackHost(want)
}

func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)

	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

func fetchLab(ctx context.Context, raw, labHost string) ([]byte, string, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			host := req.URL.Hostname()
			lab := hostOnly(labHost)
			isLab := strings.EqualFold(host, lab) ||
				(strings.EqualFold(host, "127.0.0.1") && isLoopbackHost(lab))

			if host != "" && !isLab {
				return http.ErrUseLastResponse
			}

			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, "", fmt.Errorf("ssrf request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("ssrf fetch: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBlobBytes))
	if err != nil {
		return nil, "", fmt.Errorf("ssrf body: %w", err)
	}

	final := raw
	if loc, err := resp.Location(); err == nil {
		final = loc.String()
	}

	return body, final, nil
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}

	return hostport
}

func handleF04(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if next == "" {
		reject(w, "missing next")

		return
	}

	found(w, next)
}

func handleLoginPage(w http.ResponseWriter, _ *http.Request) {
	writeHTML(w, `<!doctype html><h1>Sign in</h1><form><input name="u"><input type="password" name="p"></form>`+"\n")
}

func handleF06(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")

	u, err := url.Parse(raw)
	if err != nil || raw == "" {
		reject(w, "rejected")

		return
	}

	if u.Host != "" && !strings.EqualFold(u.Host, r.Host) && !strings.EqualFold(u.Hostname(), requestHost(r)) {
		reject(w, "off host")

		return
	}

	found(w, raw)
}

func handleF07R1(w http.ResponseWriter, _ *http.Request) {
	found(w, "/f07/r2")
}

func handleF07R2(w http.ResponseWriter, _ *http.Request) {
	found(w, "/landed")
}

func handleF09(w http.ResponseWriter, _ *http.Request) {
	writeHTML(w, `<!doctype html><a href="https://example.com/" target="_blank">ext</a>`+"\n")
}

func handleLanded(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprint(w, "landed\n")
}

type cacheStore struct {
	mu   sync.Mutex
	data map[string]string
}

func newCacheStore() *cacheStore {
	return &cacheStore{data: map[string]string{}}
}

func (c *cacheStore) put(key, loc string) {
	c.mu.Lock()
	c.data[key] = loc
	c.mu.Unlock()
}

func (c *cacheStore) get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	loc, ok := c.data[key]

	return loc, ok
}

func (l *Lab) handleF10(w http.ResponseWriter, r *http.Request) {
	cb := r.URL.Query().Get("cb")
	if cb == "" {
		reject(w, "missing cb cache buster")

		return
	}

	key := r.URL.Path + "?cb=" + cb
	xfh := r.Header.Get("X-Forwarded-Host")
	w.Header().Set("Cache-Control", "public, max-age=60")

	if xfh != "" {
		loc := "https://" + xfh + r.URL.Path
		l.poison.put(key, loc)
		w.Header().Set("X-Cache", "MISS")
		found(w, loc)

		return
	}

	if loc, ok := l.poison.get(key); ok {
		w.Header().Set("X-Cache", "HIT")
		found(w, loc)

		return
	}

	w.Header().Set("X-Cache", "MISS")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "ok\n")
}
