package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/nedlir/detour/internal/client"
	"github.com/nedlir/detour/internal/config"
	"github.com/nedlir/detour/internal/confirm"
	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/report"
	"github.com/spf13/cobra"
)

func newConfirmCmd() *cobra.Command {
	var (
		list    string
		outDir  string
		referer string
	)

	cmd := &cobra.Command{
		Use:   "confirm",
		Short: "Prove candidate findings in a real browser",
		Long: "confirm replays candidate findings in a headless browser and promotes the ones that actually " +
			"navigate. Requests to the canary or any off-scope host are aborted before they leave the browser; " +
			"the destination recorded on a finding is the captured intent, never a page that loaded.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runConfirm(cmd, list, outDir, referer)
		},
	}

	cmd.Flags().StringVarP(&list, "list", "l", "", "findings.jsonl to confirm, or - for stdin")
	cmd.Flags().StringVar(&outDir, "out", "", "write promoted findings plus screenshots and HARs here")
	cmd.Flags().StringVar(&referer, "referer-test", "", "run the referer redirect test against this URL instead")

	return cmd
}

func runConfirm(cmd *cobra.Command, list, outDir, referer string) error {
	cfg, ok := config.FromContext(cmd.Context())
	if !ok {
		return errors.New("config not loaded")
	}

	confirmer, err := newConfirmer(cfg, outDir)
	if err != nil {
		return err
	}

	if referer != "" {
		return runRefererTest(cmd, confirmer, referer, outDir)
	}

	if list == "" {
		return errors.New("confirm needs -l findings.jsonl")
	}

	findings, err := loadFindings(cmd, list)
	if err != nil {
		return err
	}

	promoted, summary, err := confirmer.Confirm(cmd.Context(), findings)
	if err != nil {
		return err
	}

	return writeConfirmOutput(cmd, promoted, summary, outDir)
}

// newConfirmer wires the scope guard and the operator's credentials into the
// browser, so the same boundary applies to Chrome as to detour's own client.
func newConfirmer(cfg config.Config, outDir string) (*confirm.Confirmer, error) {
	guard, err := guardFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	headers, err := client.Headers(cfg)
	if err != nil {
		return nil, err
	}

	cookies, err := client.Cookies(cfg)
	if err != nil {
		return nil, err
	}

	if _, err := confirm.FindChrome(); err != nil {
		return nil, fmt.Errorf("%w: install Chrome or Chromium, or set DETOUR_CHROME", err)
	}

	return confirm.New(guard, confirm.Options{
		Canary:      cfg.Destination(),
		Timeout:     cfg.Timeout * browserTimeoutFactor,
		Headers:     headers,
		Cookies:     cookies,
		ArtifactDir: outDir,
	}), nil
}

// crawlDiscover drives the authenticated headless browser to each seed and
// returns the in-scope, query-bearing URLs it requested at runtime: injection
// points a static harvest cannot see on a single-page app. A missing browser
// or a failed crawl warns and yields nothing rather than ending the run.
func crawlDiscover(cmd *cobra.Command, cfg config.Config, seeds []string) []string {
	confirmer, err := newConfirmer(cfg, "")
	if err != nil {
		slog.Warn("skipping browser crawl", "reason", err)

		return nil
	}

	found := confirmer.Crawl(cmd.Context(), seeds)
	if len(found) > 0 {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "crawl: %d runtime urls discovered in the browser\n", len(found))
	}

	return found
}

// browserTimeoutFactor stretches the per-request timeout into a page budget:
// a browser has to load subresources and run scripts, not just read a header.
const browserTimeoutFactor = 3

func loadFindings(cmd *cobra.Command, list string) ([]model.Finding, error) {
	if list != "-" {
		return report.ReadJSONL(list)
	}

	raw, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		return nil, fmt.Errorf("reading findings from stdin: %w", err)
	}

	return report.DecodeJSONL(raw)
}

func writeConfirmOutput(cmd *cobra.Command, findings []model.Finding, summary confirm.Summary, outDir string) error {
	if outDir != "" {
		if _, err := report.WriteVersion(outDir, findings, version); err != nil {
			return err
		}
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	for _, f := range findings {
		if err := enc.Encode(f); err != nil {
			return fmt.Errorf("writing finding: %w", err)
		}
	}

	_, err := fmt.Fprintf(cmd.ErrOrStderr(),
		"%d confirmed, %d attempted, %d skipped, %d failed\n",
		summary.Confirmed, summary.Attempted, summary.Skipped, summary.Failed,
	)

	return err
}

func runRefererTest(cmd *cobra.Command, confirmer *confirm.Confirmer, target, outDir string) error {
	result, err := confirmer.RefererTest(cmd.Context(), target)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")

	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("writing referer result: %w", err)
	}

	// The result document stays on stdout, because that is what callers parse.
	// The finding goes to the output directory.
	finding, ok := result.Finding()
	if !ok || outDir == "" {
		return nil
	}

	if _, err := report.WriteVersion(outDir, []model.Finding{finding}, version); err != nil {
		return err
	}

	return nil
}

// maybeConfirm runs the browser stage after a scan when --headless is given.
// A missing browser is a warning, not a failure: the findings a run already
// produced are still worth having.
func maybeConfirm(
	cmd *cobra.Command,
	cfg config.Config,
	findings []model.Finding,
	headless bool,
	outDir string,
) []model.Finding {
	if !headless || len(findings) == 0 {
		return findings
	}

	confirmer, err := newConfirmer(cfg, outDir)
	if err != nil {
		slog.Warn("skipping browser confirmation", "reason", err)

		return findings
	}

	promoted, summary, err := confirmer.Confirm(cmd.Context(), findings)
	if err != nil {
		slog.Warn("browser confirmation failed", "reason", err)

		return findings
	}

	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "browser: %d confirmed of %d attempted\n",
		summary.Confirmed, summary.Attempted)

	return promoted
}
