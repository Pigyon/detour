package client

import (
	"net/http"
	"strings"
)

const (
	headerAuthorization = "Authorization"
	headerCookie        = "Cookie"
	headerCookie2       = "Cookie2"
)

func applyCredentials(req *http.Request, extra http.Header, cookies []*http.Cookie) {
	for name, values := range extra {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	host := ""
	if req.URL != nil {
		host = req.URL.Hostname()
	}

	for _, cookie := range cookies {
		if !cookieMatches(cookie, host) {
			continue
		}

		req.AddCookie(cookie)
	}
}

func stripCredentials(req *http.Request) {
	req.Header.Del(headerAuthorization)
	req.Header.Del(headerCookie)
	req.Header.Del(headerCookie2)

	if req.URL != nil {
		req.URL.User = nil
	}
}

func cookieMatches(cookie *http.Cookie, host string) bool {
	if cookie == nil {
		return false
	}

	domain := strings.TrimPrefix(strings.ToLower(cookie.Domain), ".")
	if domain == "" {
		return true
	}

	host = strings.ToLower(host)

	return host == domain || strings.HasSuffix(host, "."+domain)
}
