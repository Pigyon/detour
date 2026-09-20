// Package corpus turns a pile of harvested URLs into the small set of
// injection points worth spending requests on: normalize, dedupe by shape,
// then classify what makes each one interesting.
package corpus

import (
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

// staticExtensions never carry a navigation destination. Dropping them early
// is the single biggest reduction on an archive dump.
var staticExtensions = map[string]struct{}{
	".css": {}, ".scss": {}, ".less": {},
	".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".svg": {}, ".ico": {},
	".webp": {}, ".avif": {}, ".bmp": {}, ".tiff": {},
	".woff": {}, ".woff2": {}, ".ttf": {}, ".otf": {}, ".eot": {},
	".mp4": {}, ".webm": {}, ".mp3": {}, ".wav": {}, ".ogg": {}, ".avi": {},
	".zip": {}, ".gz": {}, ".tar": {}, ".rar": {}, ".7z": {},
	".pdf": {}, ".doc": {}, ".docx": {}, ".xls": {}, ".xlsx": {}, ".ppt": {},
}

// defaultPorts are stripped so the same endpoint on an explicit port dedupes
// against its implicit form.
var defaultPorts = map[string]string{
	"http":  "80",
	"https": "443",
}

// Normalize canonicalizes a URL for comparison. It returns false for anything
// that is not a usable http target.
func Normalize(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", false
	}

	if !isHTTP(parsed.Scheme) || parsed.Host == "" {
		return "", false
	}

	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = normalizeHost(parsed)
	parsed.Fragment = ""
	parsed.RawFragment = ""
	parsed.User = nil
	parsed.Path = cleanPath(parsed.Path)

	if isStatic(parsed.Path) {
		return "", false
	}

	parsed.RawQuery = normalizeQuery(parsed.RawQuery)

	return parsed.String(), true
}

func isHTTP(scheme string) bool {
	lower := strings.ToLower(scheme)

	return lower == "http" || lower == "https"
}

func normalizeHost(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()

	if port == "" || port == defaultPorts[strings.ToLower(u.Scheme)] {
		return host
	}

	return host + ":" + port
}

// cleanPath collapses duplicate slashes and resolves dot segments without
// losing a meaningful trailing slash.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}

	trailing := strings.HasSuffix(p, "/")
	cleaned := path.Clean(p)

	if cleaned == "." {
		return "/"
	}

	if trailing && !strings.HasSuffix(cleaned, "/") {
		cleaned += "/"
	}

	return cleaned
}

func isStatic(p string) bool {
	ext := strings.ToLower(path.Ext(p))
	_, ok := staticExtensions[ext]

	return ok
}

// normalizeQuery sorts parameters so two URLs differing only in parameter
// order collapse together. Values are preserved: the value is often the
// destination.
func normalizeQuery(raw string) string {
	if raw == "" {
		return ""
	}

	values, err := url.ParseQuery(raw)
	if err != nil {
		return raw
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	var b strings.Builder

	for _, key := range keys {
		list := values[key]
		sort.Strings(list)

		for _, v := range list {
			if b.Len() > 0 {
				b.WriteByte('&')
			}

			b.WriteString(url.QueryEscape(key))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(v))
		}
	}

	return b.String()
}

// Shape patterns. Two URLs with the same shape test the same code path, so
// only one of them is worth attacking.
var (
	numericSegment = regexp.MustCompile(`^\d+$`)
	uuidSegment    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexSegment     = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	longSegment    = regexp.MustCompile(`^[A-Za-z0-9_-]{24,}$`)
)

// Shape reduces a URL to what actually varies: host, path with identifier
// segments folded away, and the set of parameter names.
//
// This is the uro idea. An archive dump of ten thousand /article/<id> URLs is
// one endpoint, and attacking all of them is ten thousand requests spent on
// the same validator.
func Shape(raw string) (string, bool) {
	normalized, ok := Normalize(raw)
	if !ok {
		return "", false
	}

	parsed, err := url.Parse(normalized)
	if err != nil {
		return "", false
	}

	segments := strings.Split(parsed.Path, "/")
	for i, segment := range segments {
		segments[i] = foldSegment(segment)
	}

	keys := paramNames(parsed)

	return parsed.Scheme + "://" + parsed.Host + strings.Join(segments, "/") + "?" + strings.Join(keys, "&"), true
}

func foldSegment(segment string) string {
	switch {
	case segment == "":
		return ""
	case numericSegment.MatchString(segment):
		return "{n}"
	case uuidSegment.MatchString(segment):
		return "{uuid}"
	case hexSegment.MatchString(segment):
		return "{hex}"
	case longSegment.MatchString(segment):
		return "{blob}"
	default:
		return segment
	}
}

func paramNames(u *url.URL) []string {
	values := u.Query()

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, strings.ToLower(key))
	}

	sort.Strings(keys)

	return keys
}
