package harvest

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const (
	// maxSitemapDepth bounds sitemap index recursion.
	maxSitemapDepth = 3
	// maxSitemaps bounds how many sitemap documents are read in total.
	maxSitemaps = 50
)

// freebiePaths are the files a site publishes about itself. They cost one
// request each, need no key, and routinely name endpoints no crawl reaches.
var freebiePaths = []string{
	"/robots.txt",
	"/.well-known/security.txt",
	"/security.txt",
	"/swagger.json",
	"/openapi.json",
	"/swagger/v1/swagger.json",
	"/api/swagger.json",
	"/api/openapi.json",
}

// Freebies reads the files a site publishes about itself and returns every
// URL or path they name, resolved against base.
func Freebies(ctx context.Context, client Doer, base string) ([]string, []error) {
	root, err := url.Parse(base)
	if err != nil {
		return nil, []error{fmt.Errorf("parsing target: %w", err)}
	}

	out := []string{}
	errs := []error{}

	for _, path := range freebiePaths {
		body, err := fetchBody(ctx, client, root.ResolveReference(&url.URL{Path: path}).String())
		if err != nil {
			errs = append(errs, err)

			continue
		}

		out = append(out, readFreebie(root, path, body)...)
	}

	sitemaps, sitemapErrs := Sitemaps(ctx, client, root)
	out = append(out, sitemaps...)
	errs = append(errs, sitemapErrs...)

	return out, errs
}

func readFreebie(root *url.URL, path string, body []byte) []string {
	if strings.HasSuffix(path, ".json") {
		return openAPIPaths(root, body)
	}

	return textReferences(root, body)
}

// robotsRef matches the path-bearing directives in robots.txt and the URL in
// security.txt style key/value files.
var robotsRef = regexp.MustCompile(`(?im)^\s*(?:allow|disallow|sitemap|canonical|contact|policy|hiring)\s*:\s*(\S+)`)

func textReferences(root *url.URL, body []byte) []string {
	out := []string{}

	for _, match := range robotsRef.FindAllStringSubmatch(string(body), -1) {
		value := strings.TrimSpace(match[1])
		if value == "" || value == "/" || strings.Contains(value, "*") {
			continue
		}

		if resolved, ok := resolveAgainst(root, value); ok {
			out = append(out, resolved)
		}
	}

	return out
}

// openAPIDoc is the sliver of an OpenAPI document that names endpoints.
type openAPIDoc struct {
	Paths   map[string]any `json:"paths"`
	Servers []struct {
		URL string `json:"url"`
	} `json:"servers"`
	BasePath string `json:"basePath"`
}

func openAPIPaths(root *url.URL, body []byte) []string {
	var doc openAPIDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}

	prefix := doc.BasePath
	if len(doc.Servers) > 0 && doc.Servers[0].URL != "" {
		prefix = doc.Servers[0].URL
	}

	out := make([]string, 0, len(doc.Paths))

	for path := range doc.Paths {
		joined := strings.TrimSuffix(prefix, "/") + path

		if resolved, ok := resolveAgainst(root, joined); ok {
			out = append(out, resolved)
		}
	}

	return out
}

// sitemapDoc covers both a sitemap and a sitemap index, which share a shape.
type sitemapDoc struct {
	URLs []struct {
		Loc string `xml:"loc"`
	} `xml:"url"`
	Sitemaps []struct {
		Loc string `xml:"loc"`
	} `xml:"sitemap"`
}

// Sitemaps walks sitemap.xml and any index it points at, bounded in both
// depth and total documents so a hostile or enormous site cannot run away
// with the harvest.
func Sitemaps(ctx context.Context, client Doer, root *url.URL) ([]string, []error) {
	seeds := []string{"/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"}

	queue := make([]string, 0, len(seeds))
	for _, seed := range seeds {
		queue = append(queue, root.ResolveReference(&url.URL{Path: seed}).String())
	}

	out := []string{}
	errs := []error{}
	seen := map[string]struct{}{}
	read := 0

	for depth := 0; depth <= maxSitemapDepth && len(queue) > 0 && read < maxSitemaps; depth++ {
		next := []string{}

		for _, endpoint := range queue {
			if _, dup := seen[endpoint]; dup || read >= maxSitemaps {
				continue
			}

			seen[endpoint] = struct{}{}
			read++

			locs, children, err := readSitemap(ctx, client, endpoint)
			if err != nil {
				errs = append(errs, err)

				continue
			}

			out = append(out, locs...)
			next = append(next, children...)
		}

		queue = next
	}

	return out, errs
}

func readSitemap(ctx context.Context, client Doer, endpoint string) (locs, children []string, err error) {
	body, err := fetchBody(ctx, client, endpoint)
	if err != nil {
		return nil, nil, err
	}

	var doc sitemapDoc
	if err := xml.Unmarshal(body, &doc); err != nil {
		return nil, nil, fmt.Errorf("decoding sitemap %s: %w", endpoint, err)
	}

	for _, item := range doc.URLs {
		if loc := strings.TrimSpace(item.Loc); loc != "" {
			locs = append(locs, loc)
		}
	}

	for _, item := range doc.Sitemaps {
		if loc := strings.TrimSpace(item.Loc); loc != "" {
			children = append(children, loc)
		}
	}

	return locs, children, nil
}

// sourceMapRef matches the sourceMappingURL comment a bundler leaves behind.
var sourceMapRef = regexp.MustCompile(`(?i)//[#@]\s*sourceMappingURL\s*=\s*(\S+)`)

// SourceMaps returns the .js.map URLs a script points at. The original
// sources behind them carry the guard names a minified bundle has thrown
// away, which is what makes them worth a request.
func SourceMaps(base string, script []byte) []string {
	root, err := url.Parse(base)
	if err != nil {
		return nil
	}

	out := []string{}

	for _, match := range sourceMapRef.FindAllStringSubmatch(string(script), -1) {
		ref := strings.TrimSpace(match[1])
		if ref == "" || strings.HasPrefix(ref, "data:") {
			continue
		}

		if resolved, ok := resolveAgainst(root, ref); ok {
			out = append(out, resolved)
		}
	}

	return out
}

func resolveAgainst(root *url.URL, ref string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return "", false
	}

	resolved := root.ResolveReference(parsed)
	if resolved.Host == "" {
		return "", false
	}

	scheme := strings.ToLower(resolved.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}

	return resolved.String(), true
}
