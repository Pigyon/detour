package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nedlir/detour/internal/adapter"
	"github.com/nedlir/detour/internal/attack"
	"github.com/nedlir/detour/internal/client"
	"github.com/nedlir/detour/internal/config"
	"github.com/nedlir/detour/internal/corpus"
	"github.com/nedlir/detour/internal/escalate"
	"github.com/nedlir/detour/internal/js"
	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/nuclei"
	"github.com/nedlir/detour/internal/report"
	"github.com/nedlir/detour/internal/resolve"
	"github.com/spf13/cobra"
)

const (
	dirPerm  = 0o750
	filePerm = 0o600
)

// runPipeline is the end-to-end path: surface, harvest, select, attack, and
// optionally confirm. It is what `detour https://target.com` does.
//
// Each stage narrows the one before it. The point of the ordering is that the
// attack engine, which is the only stage that spends requests on payloads,
// sees a small ranked list rather than an archive dump.
func runPipeline(cmd *cobra.Command, target string, flags *reconFlags, headless bool) error {
	cfg, ok := config.FromContext(cmd.Context())
	if !ok {
		return errors.New("config not loaded")
	}

	// Checked before recon, which is the expensive part: a misspelled
	// mechanism would otherwise surface subdomains, crawl the target, and
	// attack it, only to refuse to print what it found.
	allow, err := report.ParseFilter(flags.filter)
	if err != nil {
		return err
	}

	if err := report.Prepare(flags.outDir); err != nil {
		return err
	}

	c, err := scopedClient(cfg)
	if err != nil {
		return err
	}

	urls := pipelineURLs(cmd, cfg, c, target, flags)
	if len(urls) == 0 {
		return errors.New("nothing to attack: no injection points survived selection")
	}

	// --passive says detour never touches the target, and the attack engine is
	// the stage that spends requests on payloads. Running it anyway made the
	// flag a lie, which matters most to the operator who set it because their
	// testing window had closed.
	if flags.passive {
		return writeAttackOutput(cmd, passiveFindings(cmd, urls, flags), allow, flags.outDir)
	}

	// The js stage runs first. It is the only stage that can read what a
	// validator trusts, and running it after the attack meant the answer
	// arrived too late for the payloads that needed it.
	clientSide, allowed := jsFindings(cmd, c, urls, flags)

	eng := attack.New(c, cfg.Destination(), flags.keyword, cfg.Concurrency, nil)
	eng.SetTrustedHosts(allowed)

	closer, err := attachCheckpoint(eng, flags.resume)
	if err != nil {
		return err
	}

	defer closer()

	// A redirector that only accepts its own host is completed by another
	// redirector on that host, and selection has already found which
	// endpoints those are.
	eng.SetChainTargets(attack.ChainTargetsFrom(urls))

	findings, err := eng.Run(cmd.Context(), urls)
	if err != nil && !noteStopped(cmd, err) {
		return err
	}

	reportCoverage(cmd, eng.Coverage())

	// The client-side class is only reachable through the js stage: without it
	// a run produces no OR-C01 or OR-C02 candidate, and the browser stage only
	// promotes candidates that already exist.
	findings = append(findings, clientSide...)
	findings = append(findings, maybeNuclei(cmd, cfg, urls, flags.nuclei)...)

	findings = maybeConfirm(cmd, cfg, findings, headless, flags.outDir)
	findings = maybeEscalate(findings, flags.escalate)

	return writeAttackOutput(cmd, findings, allow, flags.outDir)
}

// passiveFindings reports what a run can know without sending the target a
// single payload: the selected injection points, and nothing claimed about
// them.
func passiveFindings(cmd *cobra.Command, urls []string, flags *reconFlags) []model.Finding {
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
		"passive: %d injection points selected, no payloads sent\n", len(urls))

	return maybeEscalate(nil, flags.escalate)
}

// maybeNuclei runs an installed nuclei binary over the same urls.
//
// It is a second opinion, so nothing about the run depends on it: a missing
// binary is reported once and the findings detour produced itself stand
// unchanged. nuclei inherits the operator's rate limit and proxy so it cannot
// be louder than the run that invoked it.
func maybeNuclei(cmd *cobra.Command, cfg config.Config, urls []string, enabled bool) []model.Finding {
	if !enabled || len(urls) == 0 {
		return nil
	}

	found, err := nuclei.Run(cmd.Context(), nuclei.Options{
		RateLimit: int(cfg.Rate),
		Timeout:   cfg.Timeout * nucleiTimeoutFactor,
		Proxy:     cfg.Proxy,
	}, urls)
	if err != nil {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "nuclei: skipped (%v)\n", err)

		return nil
	}

	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "nuclei: %d results\n", len(found))

	return found
}

// nucleiTimeoutFactor stretches the per-request timeout into a budget for a
// whole external scan.
const nucleiTimeoutFactor = 60

// maybeEscalate attaches escalation capabilities when asked.
//
// The stage is a pure function with no network access, so turning it on can
// never cause a request. What it adds is a reading of what the finding already
// proves, never a demonstration of it.
func maybeEscalate(findings []model.Finding, on bool) []model.Finding {
	if !on {
		return findings
	}

	return escalate.AnalyzeAll(findings)
}

// maxJSPages bounds the client-side pass. Reading a bundle is cheap, but
// fetching one per selected URL is not, and pages on one site share scripts.
const maxJSPages = 20

// jsFindings reads client-side code on the selected pages and returns its
// candidates.
func jsFindings(
	cmd *cobra.Command,
	c *client.Client,
	urls []string,
	flags *reconFlags,
) ([]model.Finding, []string) {
	if !flags.js || flags.passive || len(urls) == 0 {
		return nil, nil
	}

	fetcher := &httpFetcher{client: c}
	out := []model.Finding{}
	allowed := []string{}
	seen := map[string]struct{}{}

	for _, raw := range urls {
		if len(seen) >= maxJSPages {
			break
		}

		page := withoutQuery(raw)
		if _, dup := seen[page]; dup {
			continue
		}

		seen[page] = struct{}{}

		report, err := js.CollectPage(cmd.Context(), fetcher, page)
		if err != nil {
			slog.Debug("js stage skipped a page", "page", page, "reason", err)

			continue
		}

		out = append(out, report.Findings()...)

		// The hosts a guard trusts are the ones the allowlist-bypass payloads
		// have to wear. This stage is the only place they are discoverable.
		allowed = append(allowed, report.Allowlists()...)
	}

	if len(out) > 0 {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "js: %d client-side candidates from %d pages\n", len(out), len(seen))
	}

	return out, allowed
}

// withoutQuery reduces a selected URL to the page that serves it. The scripts
// are the same whatever the query string was.
func withoutQuery(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}

	parsed.RawQuery = ""
	parsed.Fragment = ""

	return parsed.String()
}

// pipelineURLs runs everything up to the attack: surface to seed hosts,
// harvest to collect, select to rank, and optionally deep discovery.
func pipelineURLs(
	cmd *cobra.Command,
	cfg config.Config,
	c *client.Client,
	target string,
	flags *reconFlags,
) []string {
	domain, _ := splitTarget(target)
	raw := []string{}

	// Surface only helps when the target is a domain rather than one URL, and
	// it is the stage most likely to be unavailable, so its failure is a
	// warning rather than the end of the run.
	if !strings.Contains(target, "://") {
		raw = append(raw, surfaceOrigins(cmd, cfg, domain, flags)...)
	}

	harvested := harvestFor(cmd.Context(), cfg, c, target, flags)
	raw = append(raw, harvested.URLs...)

	for _, msg := range harvested.Errors {
		slog.Debug("harvest source failed", "reason", msg)
	}

	warnHarvest(cmd, harvested)

	_, base := splitTarget(target)
	raw = append(raw, base)

	// Archives answer with whatever they have indexed, and for some targets
	// most of it belongs to somebody else. Without this filter a run attacks
	// third parties, which is the one mistake that ends a bounty account.
	raw = onTarget(raw, domain)

	selected := selectFrom(raw, flags.vendorOnly)

	urls := make([]string, 0, len(selected)+1)
	for _, entry := range selected {
		urls = append(urls, entry.URL)
	}

	// A target named on the command line is always attacked, even when
	// selection would not have picked it. The operator asked for it by name,
	// and selection exists to rank a harvest, not to overrule a request.
	urls = appendTarget(urls, base, flags.vendorOnly)

	if flags.deep {
		urls = append(urls, deepDiscover(cmd.Context(), c, raw, selected)...)
	}

	writePipelineArtifacts(flags.outDir, harvested.URLs, selected)

	_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
		"harvested %d urls, selected %d injection points\n", len(harvested.URLs), len(urls))

	return urls
}

// onTarget keeps only the URLs that belong to the target's own domain.
//
// A scope file is the hard boundary and is checked again on every request, but
// it is optional, and an operator who forgot one should still not have their
// run aimed at whatever an archive happened to return.
func onTarget(urls []string, domain string) []string {
	if domain == "" {
		return urls
	}

	out := make([]string, 0, len(urls))

	for _, raw := range urls {
		parsed, err := url.Parse(raw)
		if err != nil {
			continue
		}

		if resolve.HostSuffix(parsed.Hostname(), domain) {
			out = append(out, raw)
		}
	}

	return out
}

// appendTarget adds the explicitly named target unless it is already there.
// Under --vendor-only the operator asked for a narrow sweep, so the target is
// not forced in.
func appendTarget(urls []string, base string, vendorOnly bool) []string {
	if vendorOnly {
		return urls
	}

	normalized, ok := corpus.Normalize(base)
	if !ok {
		return urls
	}

	if slices.Contains(urls, normalized) {
		return urls
	}

	return append(urls, normalized)
}

func surfaceOrigins(cmd *cobra.Command, cfg config.Config, domain string, flags *reconFlags) []string {
	if flags.passive {
		return nil
	}

	mapper, err := newMapper(cfg)
	if err != nil {
		slog.Warn("skipping surface stage", "reason", err)

		return nil
	}

	result := mapper.Run(cmd.Context(), domain)

	if len(result.Priority()) > 0 {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
			"surface: %d hosts, %d delegated to a click-wrapper vendor\n",
			len(result.Hosts), len(result.Priority()))
	}

	if flags.outDir != "" {
		if err := writeArtifact(flags.outDir, "surface.json", result); err != nil {
			slog.Warn("could not write surface.json", "reason", err)
		}
	}

	return result.Origins()
}

func writePipelineArtifacts(outDir string, harvested []string, selected []corpus.Entry) {
	if outDir == "" {
		return
	}

	if err := writeArtifact(outDir, "harvested.json", harvested); err != nil {
		slog.Warn("could not write harvested.json", "reason", err)
	}

	if err := writeArtifact(outDir, "selected.json", selected); err != nil {
		slog.Warn("could not write selected.json", "reason", err)
	}
}

// loadURLs reads a URL source through the existing adapters, so select
// accepts everything attack does.
func loadURLs(cmd *cobra.Command, source string) ([]string, error) {
	if source != "-" {
		return adapter.LoadPath(source)
	}

	raw, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		return nil, fmt.Errorf("reading urls from stdin: %w", err)
	}

	return adapter.LoadBytes(raw, "stdin")
}

func scopedClient(cfg config.Config) (*client.Client, error) {
	guard, err := guardFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	return client.New(cfg, guard)
}

// writeJSON prints a value as indented JSON with a one-line summary on stderr.
func writeJSON(cmd *cobra.Command, value any, summary string) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")

	if err := enc.Encode(value); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	_, err := fmt.Fprintln(cmd.ErrOrStderr(), summary)

	return err
}

func writeArtifact(dir, name string, value any) error {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding %s: %w", name, err)
	}

	if err := os.WriteFile(filepath.Join(dir, name), append(raw, '\n'), filePerm); err != nil {
		return fmt.Errorf("writing %s: %w", name, err)
	}

	return nil
}
