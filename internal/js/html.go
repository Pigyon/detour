package js

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// Script is one piece of client-side code found in a page.
type Script struct {
	// Src is the resolved URL of an external script, empty when inline.
	Src string `json:"src,omitempty"`
	// Body is the code of an inline script.
	Body []byte `json:"-"`
}

// Document is what the static HTML pass found: the scripts worth analyzing
// and the markup-level findings that need no JS at all.
type Document struct {
	Scripts  []Script  `json:"scripts"`
	Verdicts []Verdict `json:"verdicts"`
}

// ParseHTML extracts scripts and runs the markup checks. base resolves
// relative script sources.
func ParseHTML(base string, body []byte) (Document, error) {
	root, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return Document{}, fmt.Errorf("parsing html: %w", err)
	}

	doc := Document{Scripts: []Script{}, Verdicts: []Verdict{}}
	baseURL, _ := url.Parse(base)

	walkHTML(root, func(n *html.Node) {
		switch n.Data {
		case "script":
			doc.Scripts = append(doc.Scripts, scriptFrom(n, baseURL)...)
		case "a":
			doc.Verdicts = append(doc.Verdicts, tabnabVerdict(n, baseURL)...)
		case "iframe":
			doc.Verdicts = append(doc.Verdicts, iframeVerdict(n)...)
		}
	})

	return doc, nil
}

func walkHTML(n *html.Node, visit func(*html.Node)) {
	if n.Type == html.ElementNode {
		visit(n)
	}

	for child := n.FirstChild; child != nil; child = child.NextSibling {
		walkHTML(child, visit)
	}
}

func scriptFrom(n *html.Node, base *url.URL) []Script {
	if src := attr(n, "src"); src != "" {
		return []Script{{Src: resolveRef(base, src)}}
	}

	var body strings.Builder

	for child := n.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.TextNode {
			body.WriteString(child.Data)
		}
	}

	if strings.TrimSpace(body.String()) == "" {
		return nil
	}

	return []Script{{Body: []byte(body.String())}}
}

// tabnabVerdict is the reverse tabnabbing check (OR-F09): an external link
// opening in a new tab without rel=noopener hands the opener to the
// destination. Cheap, needs no browser, and no redirect scanner looks for it.
func tabnabVerdict(n *html.Node, base *url.URL) []Verdict {
	if !strings.EqualFold(attr(n, "target"), "_blank") {
		return nil
	}

	href := attr(n, "href")
	if href == "" || !isExternal(base, href) {
		return nil
	}

	rel := strings.ToLower(attr(n, "rel"))
	if strings.Contains(rel, "noopener") || strings.Contains(rel, "noreferrer") {
		return nil
	}

	return []Verdict{{
		TechniqueID: "OR-F09",
		Severity:    SeverityCandidate,
		Sink:        "target=_blank",
		Discrepancy: "external link opens in a new tab without rel=noopener, so the destination keeps window.opener",
		Evidence:    []string{"href " + href, "rel " + quoted(rel)},
	}}
}

// iframeVerdict flags a frame rendering another document with no sandbox,
// which can drive top-level navigation (OR-C03).
//
// This is reported as info, not a candidate. A sandbox-less frame is a
// precondition, and whether the framed document is attacker-influenced cannot
// be read off the markup. Treating every embed as a lead would flood a report
// with noise; the browser stage promotes the ones that actually navigate.
func iframeVerdict(n *html.Node) []Verdict {
	if hasAttr(n, "sandbox") {
		return nil
	}

	src := attr(n, "src")
	if src == "" {
		return nil
	}

	return []Verdict{{
		TechniqueID: "OR-C03",
		Severity:    SeverityInfo,
		Sink:        "iframe",
		Discrepancy: "frame has no sandbox attribute, so its document can set top.location",
		Evidence:    []string{"src " + src},
	}}
}

func isExternal(base *url.URL, href string) bool {
	ref, err := url.Parse(href)
	if err != nil || ref.Host == "" {
		return false
	}

	return base == nil || base.Host == "" || !strings.EqualFold(ref.Hostname(), base.Hostname())
}

func resolveRef(base *url.URL, ref string) string {
	parsed, err := url.Parse(ref)
	if err != nil {
		return ref
	}

	if base == nil {
		return parsed.String()
	}

	return base.ResolveReference(parsed).String()
}

func attr(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val
		}
	}

	return ""
}

func hasAttr(n *html.Node, name string) bool {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return true
		}
	}

	return false
}

func quoted(s string) string {
	if s == "" {
		return "(absent)"
	}

	return s
}
