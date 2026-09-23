package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/nedlir/detour/internal/adapter"
	"github.com/nedlir/detour/internal/attack"
	"github.com/nedlir/detour/internal/checkpoint"
	"github.com/nedlir/detour/internal/client"
	"github.com/nedlir/detour/internal/config"
	"github.com/nedlir/detour/internal/model"
	"github.com/nedlir/detour/internal/payload"
	"github.com/nedlir/detour/internal/report"
	"github.com/spf13/cobra"
)

func newAttackCmd() *cobra.Command {
	var (
		keyword   string
		filter    string
		outDir    string
		resume    string
		headless  bool
		escalate  bool
		useNuclei bool
	)

	cmd := &cobra.Command{
		Use:   "attack source",
		Short: "Probe a URL list or stdin for open redirects",
		Long:  "attack reads a URL list, HAR, Burp export, jsonl stream, or stdin (-) and emits capability-scored findings as JSONL.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAttack(cmd, args[0], attackOptions{
				keyword: keyword, filter: filter, outDir: outDir, resume: resume,
				headless: headless, escalate: escalate, nuclei: useNuclei,
			})
		},
	}

	cmd.Flags().StringVar(&keyword, "keyword", payload.DefaultKeyword, "injection mark replaced by each payload")
	cmd.Flags().StringVar(&filter, "filter", "", "comma-separated mechanisms to report ("+strings.Join(payload.Mechanisms(), ",")+")")
	cmd.Flags().StringVar(&outDir, "out", "", "write REPORT.md, a per-finding report, and the machine formats to this directory")
	cmd.Flags().StringVar(&resume, "resume", "", "append-only checkpoint file; skip completed attempts")
	cmd.Flags().BoolVar(&headless, "headless", false, "prove candidates in a headless browser (needs Chrome)")
	cmd.Flags().BoolVar(&escalate, "escalate", false, "attach escalation capabilities; never performs the escalation")
	cmd.Flags().BoolVar(&useNuclei, "nuclei", false,
		"also run an installed nuclei binary as a second opinion; absent nuclei is a no-op")

	return cmd
}

// attackOptions are the attack command's own switches, kept together so the
// function signature does not grow a parameter per flag.
type attackOptions struct {
	keyword  string
	filter   string
	outDir   string
	resume   string
	headless bool
	escalate bool
	nuclei   bool
}

func runAttack(cmd *cobra.Command, source string, opts attackOptions) error {
	cfg, ok := config.FromContext(cmd.Context())
	if !ok {
		return errors.New("config not loaded")
	}

	// The flags that can only be wrong are settled before anything is sent. A
	// misspelled mechanism used to be caught while writing the report, which
	// meant a full scan ran, every request landed on the target, and the run
	// then exited non-zero with nothing to show for it.
	allow, err := report.ParseFilter(opts.filter)
	if err != nil {
		return err
	}

	if err := report.Prepare(opts.outDir); err != nil {
		return err
	}

	guard, err := guardFromConfig(cfg)
	if err != nil {
		return err
	}

	c, err := client.New(cfg, guard)
	if err != nil {
		return err
	}

	urls, err := adapter.LoadPath(source)
	if err != nil {
		return err
	}

	if len(urls) == 0 {
		return errors.New("no urls in source")
	}

	eng := attack.New(c, cfg.Destination(), opts.keyword, cfg.Concurrency, nil)

	// A redirector that only accepts its own host is completed by another
	// redirector on that host, and selection has already found which
	// endpoints those are.
	eng.SetChainTargets(attack.ChainTargetsFrom(urls))

	closer, err := attachCheckpoint(eng, opts.resume)
	if err != nil {
		return err
	}

	defer closer()

	findings, err := eng.Run(cmd.Context(), urls)
	if err != nil {
		return err
	}

	reportCoverage(cmd, eng.Coverage())

	findings = append(findings, maybeNuclei(cmd, cfg, urls, opts.nuclei)...)
	findings = maybeConfirm(cmd, cfg, findings, opts.headless, opts.outDir)
	findings = maybeEscalate(findings, opts.escalate)

	return writeAttackOutput(cmd, findings, allow, opts.outDir)
}

func attachCheckpoint(eng *attack.Engine, resume string) (func(), error) {
	if resume == "" {
		return func() {}, nil
	}

	store, err := checkpoint.Open(resume)
	if err != nil {
		return nil, err
	}

	eng.SetCheckpoint(store)

	return func() { _ = store.Close() }, nil
}

// reportCoverage says what the run touched, so a count of zero can be read.
func reportCoverage(cmd *cobra.Command, c attack.Coverage) {
	if c.Sources == 0 {
		return
	}

	_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
		"covered: %d of %d urls answered, %d already redirect, %d parameters probed\n",
		c.Reachable, c.Sources, c.Redirectors, c.Params)
}

func writeAttackOutput(cmd *cobra.Command, findings []model.Finding, allow map[string]struct{}, outDir string) error {
	findings = report.Apply(findings, allow)

	// Findings reach stdout before the report is written, so a directory that
	// turns out to be unwritable costs the report and not the results.
	enc := json.NewEncoder(cmd.OutOrStdout())
	for _, f := range findings {
		if err := enc.Encode(f); err != nil {
			return fmt.Errorf("writing finding: %w", err)
		}
	}

	if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "%d findings\n", len(findings)); err != nil {
		return err
	}

	if outDir == "" {
		return nil
	}

	return report.WriteVersion(outDir, findings, version)
}
