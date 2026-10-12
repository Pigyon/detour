package client

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nedlir/detour/internal/config"
)

// Cookies resolves the operator's inline and file-based cookies. The browser
// stage needs the same jar the HTTP client carries.
func Cookies(cfg config.Config) ([]*http.Cookie, error) {
	return loadCookies(cfg)
}

// loadHeaderFile reads a file of "Name: Value" lines (blank lines and lines
// starting with # are skipped) into a header set. It is the refreshable half
// of the extra headers, where a rotating bearer lives.
func loadHeaderFile(path string) (http.Header, error) {
	file, err := os.Open(path) //nolint:gosec // G304: path is the operator-supplied --headers-file.
	if err != nil {
		return nil, fmt.Errorf("opening headers file: %w", err)
	}

	defer func() { _ = file.Close() }()

	var lines []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		lines = append(lines, line)
	}

	if scanErr := scanner.Err(); scanErr != nil {
		return nil, fmt.Errorf("reading headers file: %w", scanErr)
	}

	headers, err := config.ParseHeaders(lines)
	if err != nil {
		return nil, err
	}

	return headers, nil
}

func loadCookies(cfg config.Config) ([]*http.Cookie, error) {
	cookies := parseCookieHeader(cfg.Cookie)
	if cfg.CookiesFile == "" {
		return cookies, nil
	}

	fromFile, err := parseNetscapeFile(cfg.CookiesFile)
	if err != nil {
		return nil, err
	}

	return append(cookies, fromFile...), nil
}

func parseCookieHeader(raw string) []*http.Cookie {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []*http.Cookie{}
	}

	parts := strings.Split(raw, ";")
	cookies := make([]*http.Cookie, 0, len(parts))

	for _, part := range parts {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || name == "" {
			continue
		}

		cookies = append(cookies, &http.Cookie{ //nolint:gosec // G124: replay operator-supplied cookies as given.
			Name:  strings.TrimSpace(name),
			Value: strings.TrimSpace(value),
		})
	}

	return cookies
}

func parseNetscapeFile(path string) (cookies []*http.Cookie, err error) {
	file, openErr := os.Open(path) //nolint:gosec // G304: path is the operator-supplied --cookies-file.
	if openErr != nil {
		return nil, fmt.Errorf("opening cookies file: %w", openErr)
	}

	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing cookies file: %w", cerr)
		}
	}()

	cookies = []*http.Cookie{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || (strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "#HttpOnly_")) {
			continue
		}

		httpOnly := false
		if strings.HasPrefix(line, "#HttpOnly_") {
			httpOnly = true
			line = strings.TrimPrefix(line, "#HttpOnly_")
		}

		fields := strings.Split(line, "\t")
		if len(fields) < 7 {
			continue
		}

		expires := time.Time{}
		if epoch, convErr := strconv.ParseInt(fields[4], 10, 64); convErr == nil && epoch > 0 {
			expires = time.Unix(epoch, 0)
		}

		cookies = append(cookies, &http.Cookie{ //nolint:gosec // G124: replay operator-supplied cookies as given.
			Name:     fields[5],
			Value:    fields[6],
			Path:     fields[2],
			Domain:   fields[0],
			Expires:  expires,
			Secure:   strings.EqualFold(fields[3], "TRUE"),
			HttpOnly: httpOnly,
		})
	}

	if scanErr := scanner.Err(); scanErr != nil {
		return nil, fmt.Errorf("reading cookies file: %w", scanErr)
	}

	return cookies, nil
}
