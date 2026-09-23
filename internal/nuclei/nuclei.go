// Package nuclei runs a nuclei binary over a URL list and reads its findings
// back, when the operator asks for it and the binary is installed.
//
// It is a second opinion and nothing more. nuclei is not vendored, not
// required, and never on the critical path: without it detour produces exactly
// the findings it always did, and an absent binary is a clean no-op rather
// than an error. The templates it runs are its own, so what it catches is
// whatever the community has written, which is a different axis from the
// corpus detour resolves against.
package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/payload"
)

// ErrNotInstalled is returned when no nuclei binary can be found.
var ErrNotInstalled = errors.New("nuclei is not installed")

const (
	// defaultTags restricts the run to the templates that look for this class.
	// Running the whole template set against a bounty target is somebody
	// else's scan, not this one.
	defaultTags = "redirect"

	// maxOutput bounds what is read back from the binary.
	maxOutput = 16 << 20

	// binary is the executable name looked up on PATH.
	binary = "nuclei"
)

// Options configures one nuclei run.
type Options struct {
	// Binary overrides the executable. Empty means look up "nuclei" on PATH.
	Binary string
	// Tags selects templates. Empty means the redirect tag.
	Tags string
	// RateLimit is requests per second, so nuclei honours the same ceiling
	// the rest of the run does.
	RateLimit int
	// Timeout bounds the whole run.
	Timeout time.Duration
	// Proxy routes nuclei through the operator's proxy.
	Proxy string
}

// Find reports whether a usable nuclei binary exists.
func Find(opts Options) (string, error) {
	name := opts.Binary
	if name == "" {
		name = binary
	}

	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrNotInstalled, name)
	}

	return path, nil
}

// Run scans urls and returns nuclei's findings as detour findings.
//
// A missing binary returns ErrNotInstalled and no findings, which callers
// treat as "not asked for" rather than as a failure.
func Run(ctx context.Context, opts Options, urls []string) ([]model.Finding, error) {
	path, err := Find(opts)
	if err != nil {
		return nil, err
	}

	if len(urls) == 0 {
		return nil, nil
	}

	list, cleanup, err := writeList(urls)
	if err != nil {
		return nil, err
	}

	defer cleanup()

	if opts.Timeout > 0 {
		var cancel context.CancelFunc

		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	var stdout bytes.Buffer

	cmd := exec.CommandContext(ctx, path, args(opts, list)...) //nolint:gosec // G204: path is resolved from PATH and the args are built here.
	cmd.Stdout = &stdout
	cmd.Stderr = nil

	// A non-zero exit means nuclei had nothing to say or could not run. Either
	// way the rest of the scan stands, so the output is parsed regardless.
	_ = cmd.Run()

	return parse(stdout.Bytes()), nil
}

// args builds the command line. JSONL on stdout, no interactive output, and
// the operator's limits carried through.
func args(opts Options, list string) []string {
	tags := opts.Tags
	if tags == "" {
		tags = defaultTags
	}

	out := []string{
		"-list", list,
		"-tags", tags,
		"-jsonl",
		"-silent",
		"-no-color",
		"-disable-update-check",
	}

	if opts.RateLimit > 0 {
		out = append(out, "-rate-limit", strconv.Itoa(opts.RateLimit))
	}

	if opts.Proxy != "" {
		out = append(out, "-proxy", opts.Proxy)
	}

	return out
}

func writeList(urls []string) (string, func(), error) {
	file, err := os.CreateTemp("", "detour-nuclei-*.txt")
	if err != nil {
		return "", nil, fmt.Errorf("creating nuclei url list: %w", err)
	}

	cleanup := func() { _ = os.Remove(file.Name()) }

	if _, err := file.WriteString(strings.Join(urls, "\n") + "\n"); err != nil {
		_ = file.Close()

		cleanup()

		return "", nil, fmt.Errorf("writing nuclei url list: %w", err)
	}

	if err := file.Close(); err != nil {
		cleanup()

		return "", nil, fmt.Errorf("closing nuclei url list: %w", err)
	}

	return file.Name(), cleanup, nil
}

// result is the subset of nuclei's jsonl detour reads.
type result struct {
	TemplateID string `json:"template-id"`
	Matched    string `json:"matched-at"`
	Host       string `json:"host"`
	Info       struct {
		Name string `json:"name"`
	} `json:"info"`
}

// parse reads nuclei's jsonl, skipping anything it cannot understand.
func parse(raw []byte) []model.Finding {
	out := []model.Finding{}

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), maxOutput)

	for scanner.Scan() {
		var res result
		if err := json.Unmarshal(scanner.Bytes(), &res); err != nil {
			continue
		}

		if res.TemplateID == "" {
			continue
		}

		out = append(out, finding(res))
	}

	return out
}

// finding turns one nuclei result into a detour finding, labelled as a second
// opinion so nobody mistakes it for something detour resolved itself.
func finding(res result) model.Finding {
	target := res.Matched
	if target == "" {
		target = res.Host
	}

	f := model.NewFinding()
	f.TechniqueID = ""
	f.Mechanism = payload.MechNuclei
	f.Verdict = model.VerdictCandidate
	f.Candidate = model.NewNavigationCandidate(target, model.RepresentationQueryParameter)
	f.ProbeURL = target
	f.Repro = "nuclei -id " + res.TemplateID + " -u " + target
	f.Rationale = "reported by the nuclei template " + res.TemplateID +
		", which detour did not verify itself"
	f.Evidence = []string{
		"nuclei_template=" + res.TemplateID,
		"nuclei_name=" + res.Info.Name,
		"matched_at=" + target,
	}

	return f
}
