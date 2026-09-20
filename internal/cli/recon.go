package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/nedlir/detour/internal/client"
	"github.com/nedlir/detour/internal/config"
	"github.com/nedlir/detour/internal/corpus"
	"github.com/nedlir/detour/internal/dork"
	"github.com/nedlir/detour/internal/harvest"
	"github.com/nedlir/detour/internal/hidden"
	"github.com/nedlir/detour/internal/surface"
	"github.com/spf13/cobra"
)

// reconFlags are shared by the recon commands and the end-to-end run.
type reconFlags struct {
	passive    bool
	vendorOnly bool
	deep       bool
	crawl      bool
	depth      int
	outDir     string
}

func (r *reconFlags) register(cmd *cobra.Command) {
	fs := cmd.Flags()
	fs.BoolVar(&r.passive, "passive", false, "archives and imports only; never touch the target")
	fs.BoolVar(&r.vendorOnly, "vendor-only", false, "keep only known ESP and martech click wrappers")
	fs.BoolVar(&r.deep, "deep", false, "brute-force hidden redirect parameters on endpoints with no candidate")
	fs.BoolVar(&r.crawl, "crawl", true, "crawl the target for URLs (ignored under --passive)")
	fs.IntVar(&r.depth, "depth", 3, "crawl depth")
	fs.StringVar(&r.outDir, "out", "", "write results to this directory")
}

func newHarvestCmd() *cobra.Command {
	flags := &reconFlags{}

	cmd := &cobra.Command{
		Use:   "harvest target",
		Short: "Collect URLs for a target from archives, its own files, and a crawl",
		Long: "harvest pulls URLs from public archives (wayback, commoncrawl, otx, urlscan), from the files a " +
			"site publishes about itself (robots.txt, sitemaps, security.txt, OpenAPI), and from a crawl. " +
			"--passive keeps the run entirely off the target.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHarvest(cmd, args[0], flags)
		},
	}

	flags.register(cmd)

	return cmd
}

func runHarvest(cmd *cobra.Command, target string, flags *reconFlags) error {
	cfg, ok := config.FromContext(cmd.Context())
	if !ok {
		return errors.New("config not loaded")
	}

	c, err := scopedClient(cfg)
	if err != nil {
		return err
	}

	result := harvestFor(cmd.Context(), c, target, flags)

	return writeJSON(cmd, result, fmt.Sprintf("%d urls from %d sources", len(result.URLs), len(result.Sources)))
}

// harvestFor runs the harvest stage for a target, which may be a bare domain
// or a full URL.
func harvestFor(ctx context.Context, c *client.Client, target string, flags *reconFlags) harvest.Result {
	domain, base := splitTarget(target)

	opts := harvest.Options{Passive: flags.passive}
	if !flags.passive && flags.crawl {
		opts.Crawler = harvest.NewCrawler(c, harvest.CrawlOptions{
			Depth:    flags.depth,
			JSCrawl:  true,
			SameHost: true,
		})
	}

	return harvest.New(c, opts).Run(ctx, domain, base)
}

func newSurfaceCmd() *cobra.Command {
	var outDir string

	cmd := &cobra.Command{
		Use:   "surface domain",
		Short: "Enumerate, resolve, and probe a target's hosts",
		Long: "surface enumerates subdomains, resolves them, and probes what answers. Hosts whose CNAME points " +
			"at an email or marketing platform are flagged first: that vendor's click wrapper then runs on a " +
			"first-party domain every allowlist trusts.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSurface(cmd, args[0], outDir)
		},
	}

	cmd.Flags().StringVar(&outDir, "out", "", "write surface.json to this directory")

	return cmd
}

func runSurface(cmd *cobra.Command, domain, outDir string) error {
	cfg, ok := config.FromContext(cmd.Context())
	if !ok {
		return errors.New("config not loaded")
	}

	mapper, err := newMapper(cfg)
	if err != nil {
		return err
	}

	result := mapper.Run(cmd.Context(), strings.TrimSpace(domain))

	if outDir != "" {
		if err := writeArtifact(outDir, "surface.json", result); err != nil {
			return err
		}
	}

	return writeJSON(cmd, result,
		fmt.Sprintf("%d hosts, %d vendor-delegated", len(result.Hosts), len(result.Priority())))
}

func newMapper(cfg config.Config) (*surface.Mapper, error) {
	resolver, err := surface.NewDNSResolver()
	if err != nil {
		return nil, err
	}

	prober, err := surface.NewHTTPProber()
	if err != nil {
		return nil, err
	}

	return surface.New(surface.Options{
		Enumerator:  surface.NewSubfinder(cfg.Concurrency),
		Resolver:    resolver,
		Prober:      prober,
		Concurrency: cfg.Concurrency,
	}), nil
}

func newSelectCmd() *cobra.Command {
	var (
		vendorOnly bool
		outDir     string
	)

	cmd := &cobra.Command{
		Use:   "select source",
		Short: "Normalize, dedupe, and classify a URL list into injection points",
		Long: "select reads a URL list, HAR, Burp export, jsonl stream, or stdin (-), collapses URLs that test " +
			"the same code path, and keeps only the ones carrying a plausible injection point, highest value " +
			"first.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSelect(cmd, args[0], vendorOnly, outDir)
		},
	}

	cmd.Flags().BoolVar(&vendorOnly, "vendor-only", false, "keep only known ESP and martech click wrappers")
	cmd.Flags().StringVar(&outDir, "out", "", "write selected.jsonl to this directory")

	return cmd
}

func runSelect(cmd *cobra.Command, source string, vendorOnly bool, outDir string) error {
	urls, err := loadURLs(cmd, source)
	if err != nil {
		return err
	}

	selected := selectFrom(urls, vendorOnly)

	if outDir != "" {
		if err := writeArtifact(outDir, "selected.json", selected); err != nil {
			return err
		}
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	for _, entry := range selected {
		if err := enc.Encode(entry); err != nil {
			return fmt.Errorf("writing entry: %w", err)
		}
	}

	_, err = fmt.Fprintf(cmd.ErrOrStderr(), "%d of %d urls selected\n", len(selected), len(urls))

	return err
}

// selectFrom is the corpus stage: normalize, dedupe by shape, classify.
func selectFrom(urls []string, vendorOnly bool) []corpus.Entry {
	c := corpus.New()
	c.AddAll(urls)

	entries := c.Entries()
	if !vendorOnly {
		return entries
	}

	out := []corpus.Entry{}

	for _, entry := range entries {
		if entry.Has(corpus.KindVendorSig) {
			out = append(out, entry)
		}
	}

	return out
}

func newDorksCmd() *cobra.Command {
	var raw bool

	cmd := &cobra.Command{
		Use:   "dorks domain",
		Short: "Generate redirect-shaped search queries for a target",
		Long: "dorks generates search queries offline. Nothing is sent anywhere, so it costs no requests and " +
			"needs no key; paste the queries wherever you like.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			queries := dork.Generate(args[0])

			if raw {
				for _, q := range queries {
					if _, err := fmt.Fprintln(cmd.OutOrStdout(), q.Query); err != nil {
						return fmt.Errorf("writing query: %w", err)
					}
				}

				return nil
			}

			return writeJSON(cmd, queries, fmt.Sprintf("%d queries", len(queries)))
		},
	}

	cmd.Flags().BoolVar(&raw, "raw", false, "print bare queries, one per line")

	return cmd
}

// deepDiscover brute-forces hidden parameters on endpoints the cheap signals
// left with nothing, and returns the probes worth attacking.
func deepDiscover(ctx context.Context, c *client.Client, urls []string, selected []corpus.Entry) []string {
	covered := map[string]struct{}{}
	for _, entry := range selected {
		covered[entry.URL] = struct{}{}
	}

	finder := hidden.New(c, hidden.Options{})
	out := []string{}

	for _, raw := range urls {
		normalized, ok := corpus.Normalize(raw)
		if !ok {
			continue
		}

		if _, done := covered[normalized]; done {
			continue
		}

		hits, err := finder.Discover(ctx, normalized)
		if err != nil {
			continue
		}

		out = append(out, hidden.Promote(hits)...)
		covered[normalized] = struct{}{}
	}

	return out
}

// splitTarget accepts either a bare domain or a URL and returns both forms.
func splitTarget(target string) (domain, base string) {
	target = strings.TrimSpace(target)

	if !strings.Contains(target, "://") {
		return strings.Trim(strings.ToLower(target), "/"), "https://" + target
	}

	parsed, err := url.Parse(target)
	if err != nil || parsed.Hostname() == "" {
		return target, target
	}

	return strings.ToLower(parsed.Hostname()), target
}
