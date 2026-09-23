package report

import (
	"fmt"
	"strings"

	"github.com/nedlir/detour/internal/model"
)

// Render writes one finding as a report a researcher can submit as written.
//
// It answers the three questions a triager asks, in order: what is it, where
// is it, and how do I see it for myself.
func Render(f model.Finding) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# %s\n\n", heading(f))
	fmt.Fprintf(&b, "**Technique:** %s\n\n", techniqueLine(f.TechniqueID))
	fmt.Fprintf(&b, "**Endpoint:** %s\n\n", f.Candidate.SourceURL)

	if f.Candidate.ParamName != "" {
		fmt.Fprintf(&b, "**Parameter:** `%s`\n\n", f.Candidate.ParamName)
	}

	fmt.Fprintf(&b, "**Delivered via:** %s\n\n", mechanismLine(f.Mechanism))

	writeProof(&b, f)
	writeExplanation(&b, f)
	writeArtifactList(&b, f)

	fmt.Fprintf(&b, "## Remediation\n\n%s\n", Remediation(f.TechniqueID))

	return b.String()
}

// heading names the finding: what it is, where, and in which parameter when
// there is one.
func heading(f model.Finding) string {
	out := techniqueTitle(f.TechniqueID)

	if f.Candidate.ParamName != "" {
		out += " in `" + f.Candidate.ParamName + "`"
	}

	if host := hostOf(f); host != "" {
		out += " on " + host
	}

	return out
}

// writeProof is the part a triager runs.
func writeProof(b *strings.Builder, f model.Finding) {
	b.WriteString("## Proof of concept\n\n")

	if f.ProbeURL != "" {
		fmt.Fprintf(b, "Request:\n\n```\n%s\n```\n\n", f.Repro)
	}

	if dest := destinationOf(f); dest != "" {
		fmt.Fprintf(b, "Response:\n\n```\n%s\n```\n\n", dest)
	}

	b.WriteString("Open the request URL in a browser and the navigation ends on the destination above.\n\n")
}

// writeExplanation says why the validator let it through.
func writeExplanation(b *strings.Builder, f model.Finding) {
	rationale := f.Rationale
	if rationale == "" {
		rationale = techniqueRationale(f.TechniqueID)
	}

	if rationale == "" {
		return
	}

	fmt.Fprintf(b, "## Why it works\n\n%s\n\n", sentence(rationale))
}

func writeArtifactList(b *strings.Builder, f model.Finding) {
	if len(f.Artifacts) == 0 {
		return
	}

	b.WriteString("## Attached\n\n")

	for _, name := range f.Artifacts {
		fmt.Fprintf(b, "- `%s`\n", name)
	}

	b.WriteString("\n")
}

// destinationOf pulls the status line and the destination out of the evidence,
// which is what a reader needs to see and nothing more.
func destinationOf(f model.Finding) string {
	keep := []string{}

	for _, line := range f.Evidence {
		switch {
		case strings.HasPrefix(line, "status "):
			keep = append(keep, strings.ToUpper(line))
		case strings.HasPrefix(line, "Location: "),
			strings.HasPrefix(line, "refresh: "),
			strings.HasPrefix(line, "meta: "),
			strings.HasPrefix(line, "header: "),
			strings.HasPrefix(line, "blob: "),
			strings.HasPrefix(line, "js: "),
			strings.HasPrefix(line, "path: "),
			strings.HasPrefix(line, "host: "):
			keep = append(keep, line)
		}
	}

	return strings.Join(keep, "\n")
}

// sentence makes a rationale read as prose in a report someone submits.
func sentence(text string) string {
	if text == "" {
		return text
	}

	out := strings.ToUpper(text[:1]) + text[1:]
	if !strings.HasSuffix(out, ".") {
		out += "."
	}

	return out
}

func hostOf(f model.Finding) string {
	rest := f.Candidate.SourceURL
	if _, after, found := strings.Cut(rest, "://"); found {
		rest = after
	}

	host, _, _ := strings.Cut(rest, "/")

	return host
}

// mechanismLine names how the destination reached the browser.
func mechanismLine(mechanism string) string {
	switch mechanism {
	case "query":
		return "a query parameter reflected into the redirect"
	case "path":
		return "the request path reflected into the redirect"
	case "header":
		return "a request header reflected into the redirect"
	case "host":
		return "a parameter interpolated into the destination host"
	case "crlf":
		return "a second Location header injected with CRLF"
	case "meta":
		return "a meta refresh tag in the response body"
	case "refresh":
		return "a Refresh response header"
	case "blob":
		return "a destination inside an encoded envelope"
	case "js":
		return "a navigation sink in client-side code"
	case "hpp":
		return "a duplicated parameter the validator and the sink read differently"
	case "nuclei":
		return "an external nuclei template, not verified by detour"
	default:
		return mechanism
	}
}
