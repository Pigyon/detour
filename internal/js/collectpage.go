package js

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Fetcher retrieves a URL's body. The CLI supplies one backed by the scoped
// HTTP client, so the scope guard governs every request this package causes.
type Fetcher interface {
	Get(ctx context.Context, rawURL string) ([]byte, error)
}

// PageReport is a whole page: its markup findings, every script it pulls in,
// and the combined verdicts.
type PageReport struct {
	URL      string    `json:"url"`
	Document Document  `json:"document"`
	Scripts  []Report  `json:"scripts"`
	Verdicts []Verdict `json:"verdicts"`
	Dangling []string  `json:"dangling_hosts,omitempty"`
	// Errors records what could not be fetched or parsed, so a report never
	// looks complete when it is not.
	Errors []string `json:"errors,omitempty"`
}

// sourceMap is the subset of a .js.map detour reads.
type sourceMap struct {
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

// CollectPage analyzes a page and every script it references. External
// scripts prefer their published source map: original sources carry the guard
// names and structure a minified bundle has thrown away.
func CollectPage(ctx context.Context, f Fetcher, pageURL string) (PageReport, error) {
	body, err := f.Get(ctx, pageURL)
	if err != nil {
		return PageReport{}, fmt.Errorf("fetching %s: %w", pageURL, err)
	}

	doc, err := ParseHTML(pageURL, body)
	if err != nil {
		return PageReport{}, err
	}

	report := PageReport{
		URL:      pageURL,
		Document: doc,
		Scripts:  []Report{},
		Verdicts: append([]Verdict{}, doc.Verdicts...),
		Errors:   []string{},
	}

	// A page served as a bare script analyzes as one.
	if len(doc.Scripts) == 0 && looksLikeScript(pageURL, body) {
		doc.Scripts = []Script{{Body: body}}
	}

	for _, script := range doc.Scripts {
		report.add(collectScript(ctx, f, pageURL, script))
	}

	return report, nil
}

func (p *PageReport) add(reports []Report, errs []string) {
	p.Scripts = append(p.Scripts, reports...)
	p.Errors = append(p.Errors, errs...)

	for _, r := range reports {
		p.Verdicts = append(p.Verdicts, r.Verdicts...)
	}
}

// collectScript analyzes one script tag, following its source map when there
// is one.
func collectScript(ctx context.Context, f Fetcher, pageURL string, script Script) ([]Report, []string) {
	if script.Src == "" {
		r, err := Analyze(pageURL+" (inline)", script.Body)
		if err != nil {
			return nil, []string{err.Error()}
		}

		return []Report{r}, nil
	}

	code, err := f.Get(ctx, script.Src)
	if err != nil {
		return nil, []string{fmt.Sprintf("fetching %s: %v", script.Src, err)}
	}

	if reports, ok := fromSourceMap(ctx, f, script.Src); ok {
		return reports, nil
	}

	r, err := Analyze(script.Src, code)
	if err != nil {
		return nil, []string{err.Error()}
	}

	return []Report{r}, nil
}

// fromSourceMap analyzes the original sources a bundle publishes alongside it.
// A missing or contentless map is not an error, just an absent shortcut.
func fromSourceMap(ctx context.Context, f Fetcher, scriptURL string) ([]Report, bool) {
	raw, err := f.Get(ctx, scriptURL+".map")
	if err != nil {
		return nil, false
	}

	var sm sourceMap
	if err := json.Unmarshal(raw, &sm); err != nil || len(sm.SourcesContent) == 0 {
		return nil, false
	}

	out := []Report{}

	for i, content := range sm.SourcesContent {
		if strings.TrimSpace(content) == "" {
			continue
		}

		name := scriptURL + ".map"
		if i < len(sm.Sources) {
			name = sm.Sources[i]
		}

		r, err := Analyze(name, []byte(content))
		if err != nil {
			continue
		}

		out = append(out, r)
	}

	return out, len(out) > 0
}

// Allowlists gathers every host any guard on the page trusts, for the
// dangling-domain pass.
func (p PageReport) Allowlists() []string {
	out := []string{}

	for _, r := range p.Scripts {
		for _, v := range r.Validators {
			out = append(out, v.Allowlist...)
		}
	}

	return out
}

// ResolveDangling looks up every allowlisted host and records the ones that do
// not exist.
func (p *PageReport) ResolveDangling(ctx context.Context, r HostResolver) {
	dangling := DanglingHosts(ctx, r, p.Allowlists())
	if len(dangling) == 0 {
		return
	}

	p.Dangling = dangling
	p.Verdicts = append(p.Verdicts, DanglingVerdicts(dangling)...)
}

func looksLikeScript(pageURL string, body []byte) bool {
	if strings.HasSuffix(strings.ToLower(pageURL), ".js") {
		return true
	}

	head := strings.TrimSpace(string(body))
	if len(head) > 256 {
		head = head[:256]
	}

	return head != "" && !strings.HasPrefix(head, "<")
}
