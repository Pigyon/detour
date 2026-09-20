package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/nedlir/detour/internal/client"
	"github.com/nedlir/detour/internal/config"
	"github.com/nedlir/detour/internal/js"
	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/report"
	"github.com/spf13/cobra"
)

// maxScriptBytes caps a single fetched script. Bundles are large; a response
// bigger than this is not one detour needs to read.
const maxScriptBytes = 16 << 20

func newJSCmd() *cobra.Command {
	var (
		outDir   string
		dns      bool
		findOut  bool
		headless bool
	)

	cmd := &cobra.Command{
		Use:   "js target",
		Short: "Find navigation sinks in client-side code and read their guards",
		Long: "js reads a page or script, finds every navigation sink, traces each one back to the guard " +
			"protecting it, and reports what that guard actually treats as safe. Guards are recognized by " +
			"what they do, never by name. Every result is a candidate until a browser confirms it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runJS(cmd, args[0], outDir, dns, findOut, headless)
		},
	}

	cmd.Flags().StringVar(&outDir, "out", "", "write findings.jsonl, findings.json, and report.md to this directory")
	cmd.Flags().BoolVar(&dns, "dns", false, "resolve every allowlisted host and flag the ones that do not exist")
	cmd.Flags().BoolVar(&findOut, "findings", false, "emit findings as JSONL instead of the full analysis")
	cmd.Flags().BoolVar(&headless, "headless", false, "prove candidates in a headless browser (needs Chrome)")

	return cmd
}

func runJS(cmd *cobra.Command, target, outDir string, dns, findOut, headless bool) error {
	cfg, ok := config.FromContext(cmd.Context())
	if !ok {
		return errors.New("config not loaded")
	}

	fetcher, err := jsFetcher(cfg, target)
	if err != nil {
		return err
	}

	page, err := js.CollectPage(cmd.Context(), fetcher, target)
	if err != nil {
		return err
	}

	if dns {
		page.ResolveDangling(cmd.Context(), nil)
	}

	if err := writeJSOutput(cmd, cfg, page, outDir, findOut, headless); err != nil {
		return err
	}

	_, err = fmt.Fprintf(cmd.ErrOrStderr(), "%d sinks, %d verdicts\n", countSinks(page), len(page.Verdicts))

	return err
}

func countSinks(page js.PageReport) int {
	total := 0
	for _, r := range page.Scripts {
		total += len(r.Sinks)
	}

	return total
}

func writeJSOutput(
	cmd *cobra.Command,
	cfg config.Config,
	page js.PageReport,
	outDir string,
	findOut, headless bool,
) error {
	findings := maybeConfirm(cmd, cfg, page.Findings(), headless, outDir)

	if outDir != "" {
		if err := report.Write(outDir, findings); err != nil {
			return err
		}
	}

	enc := json.NewEncoder(cmd.OutOrStdout())

	if findOut {
		return encodeFindings(enc, findings)
	}

	enc.SetIndent("", "  ")

	if err := enc.Encode(page); err != nil {
		return fmt.Errorf("writing js report: %w", err)
	}

	return nil
}

func encodeFindings(enc *json.Encoder, findings []model.Finding) error {
	for _, f := range findings {
		if err := enc.Encode(f); err != nil {
			return fmt.Errorf("writing finding: %w", err)
		}
	}

	return nil
}

// jsFetcher serves local paths from disk and everything else through the
// scoped HTTP client, so analyzing a saved bundle needs no network at all.
func jsFetcher(cfg config.Config, target string) (js.Fetcher, error) {
	if isLocalPath(target) {
		return fileFetcher{}, nil
	}

	guard, err := guardFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	c, err := client.New(cfg, guard)
	if err != nil {
		return nil, err
	}

	return &httpFetcher{client: c}, nil
}

func isLocalPath(target string) bool {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return false
	}

	u, err := url.Parse(target)

	return err != nil || u.Scheme == "" || u.Scheme == "file"
}

// fileFetcher reads a script from disk.
type fileFetcher struct{}

func (fileFetcher) Get(_ context.Context, path string) ([]byte, error) {
	raw, err := os.ReadFile(strings.TrimPrefix(path, "file://"))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	return raw, nil
}

// httpFetcher pulls scripts through the shared scoped client, so the scope
// guard and any configured credentials apply to script fetches too.
type httpFetcher struct {
	client *client.Client
}

func (h *httpFetcher) Get(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	resp, err := h.client.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", rawURL, err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("fetching %s: status %d", rawURL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxScriptBytes))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", rawURL, err)
	}

	return body, nil
}
