package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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
		deep      bool
	)

	cmd := &cobra.Command{
		Use:   "attack source",
		Short: "Probe a URL list or stdin for open redirects",
		Long:  "attack reads a URL list, HAR, Burp export, jsonl stream, or stdin (-) and emits capability-scored findings as JSONL.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAttack(cmd, args[0], attackOptions{
				keyword: keyword, filter: filter, outDir: outDir, resume: resume,
				headless: headless, escalate: escalate, nuclei: useNuclei, deep: deep,
			})
		},
	}

	cmd.Flags().StringVar(&keyword, "keyword", payload.DefaultKeyword, "injection mark replaced by each payload")
	cmd.Flags().StringVar(&filter, "filter", "", "comma-separated mechanisms to report ("+strings.Join(payload.Mechanisms(), ",")+")")
	cmd.Flags().StringVar(&outDir, "out", "", "write REPORT.md, a per-finding report, and the machine formats to this directory")
	cmd.Flags().StringVar(&resume, "resume", "", "append-only checkpoint file; skip completed attempts")
	cmd.Flags().BoolVar(&deep, "deep", false, "brute-force hidden redirect parameters on endpoints with no candidate")
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
	deep     bool
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

	if err := c.VerifyAuth(cmd.Context()); err != nil {
		return err
	}

	// A lost session cancels the run the same way a budget or Ctrl-C does, so
	// the watcher gets a context it can stop and the scan reports what it
	// proved before the session died.
	ctx, stop := context.WithCancel(cmd.Context())
	defer stop()

	c.WatchAuth(ctx, stop)

	urls, err := adapter.LoadPath(source)
	if err != nil {
		return err
	}

	if len(urls) == 0 {
		return errors.New("no urls in source")
	}

	// --deep brute-forces hidden redirect parameters on the loaded endpoints,
	// the same discovery the full pipeline runs. Without it, attacking a saved
	// URL list only tests parameters already present, so a path-only surface
	// reports nothing probed.
	if opts.deep {
		urls = append(urls, deepDiscover(ctx, c, urls, nil)...)
	}

	eng := attack.New(c, cfg.Destination(), opts.keyword, cfg.Concurrency, nil)

	// A redirector that only accepts its own host is completed by another
	// redirector on that host, and selection has already found which
	// endpoints those are.
	eng.SetChainTargets(attack.ChainTargetsFrom(urls))

	closer, err := attachCheckpoint(eng, resolveResume(opts, source, cfg))
	if err != nil {
		return err
	}

	defer closer()

	findings, err := runEngineWithBudgets(ctx, cmd, eng, urls, cfg)
	if err != nil && !noteStopped(cmd, err) {
		return err
	}

	reportCoverage(cmd, eng.Coverage())

	findings = append(findings, maybeNuclei(cmd, cfg, urls, opts.nuclei)...)
	findings = maybeConfirm(cmd, cfg, findings, opts.headless, opts.outDir)
	findings = maybeEscalate(findings, opts.escalate)

	return writeAttackOutput(cmd, findings, allow, opts.outDir, eng.Coverage().OpaqueEnvelopes)
}

// runEngineWithBudgets runs the attack engine, honoring --budget-expand: each
// time a round's budget cuts the run short it resumes under the next budget
// (the checkpoint re-emits what was already proved, so findings accumulate
// rather than reset), until a round finishes within its budget or the list is
// exhausted. With no --budget-expand it runs once under ctx, where the single
// --budget or no limit already applies.
func runEngineWithBudgets(
	ctx context.Context,
	cmd *cobra.Command,
	eng *attack.Engine,
	urls []string,
	cfg config.Config,
) ([]model.Finding, error) {
	rounds, err := cfg.BudgetRounds()
	if err != nil {
		return nil, err
	}

	if len(rounds) == 0 {
		return eng.Run(ctx, urls)
	}

	var findings []model.Finding

	for round, budget := range rounds {
		roundCtx := ctx
		cancel := context.CancelFunc(func() {})

		if budget > 0 {
			roundCtx, cancel = context.WithTimeout(ctx, budget)
		}

		got, runErr := eng.Run(roundCtx, urls)

		cancel()

		if got != nil {
			findings = got
		}

		// Only a round that ran out its own budget advances to the next one. A
		// clean finish, a real error, or the parent context being cancelled
		// (Ctrl-C, a lost session) all end the loop here.
		if !errors.Is(runErr, context.DeadlineExceeded) || ctx.Err() != nil {
			return findings, runErr
		}

		_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
			"budget round %d of %d (%s) ran out, resuming with more time\n", round+1, len(rounds), budget)
	}

	_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
		"all %d budget rounds used; reporting what was proved so far\n", len(rounds))

	return findings, nil
}

// resolveResume picks the checkpoint path: the operator's --resume when given,
// otherwise a default one when --budget-expand is set, since resuming across
// rounds needs a checkpoint to carry what each round proved.
func resolveResume(opts attackOptions, source string, cfg config.Config) string {
	if opts.resume != "" {
		return opts.resume
	}

	if cfg.BudgetExpand != "" {
		return budgetResumePath(source, opts.outDir)
	}

	return ""
}

// budgetResumePath picks a checkpoint path for --budget-expand when the
// operator gave no --resume: under --out when there is one, otherwise a
// per-source file in the temp directory.
func budgetResumePath(source, outDir string) string {
	if outDir != "" {
		return filepath.Join(outDir, "resume.ndjson")
	}

	return filepath.Join(os.TempDir(), "detour-resume-"+slugify(source)+".ndjson")
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

// noteStopped reports whether err is the run being stopped rather than
// failing, and says so on stderr.
//
// A stopped run still writes everything it proved. Returning the error
// instead printed nothing, wrote no report, and exited non-zero, so Ctrl-C on
// a long scan cost the whole scan unless --resume happened to be set.
func noteStopped(cmd *cobra.Command, err error) bool {
	if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	_, _ = fmt.Fprintln(cmd.ErrOrStderr(),
		"stopped early: reporting what was proved before the stop")

	return true
}

// reportCoverage says what the run touched, so a count of zero can be read.
func reportCoverage(cmd *cobra.Command, c attack.Coverage) {
	if c.Sources == 0 {
		return
	}

	_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
		"covered: %d of %d urls answered, %d already redirect, %d parameters probed\n",
		c.Reachable, c.Sources, c.Redirectors, c.Params)

	for _, u := range c.RedirectorURLs {
		slog.Debug("already redirects", "url", u)
	}

	for _, u := range c.OpaqueEnvelopes {
		slog.Debug("opaque envelope found, no automatic bypass confirmed; see detour decode", "url", u)
	}
}

func writeAttackOutput(
	cmd *cobra.Command, findings []model.Finding, allow map[string]struct{}, outDir string, opaqueEnvelopes []string,
) error {
	findings = report.Apply(findings, allow)
	findings = suggestSeverities(findings)

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

	diff, err := report.WriteVersion(outDir, findings, version)
	if err != nil {
		return err
	}

	reportDiff(cmd, diff)

	return report.WriteOpaqueEnvelopes(outDir, opaqueEnvelopes)
}

// reportDiff says what changed since a previous run into the same --out,
// when there was one. Silent on a first run (nothing pre-existed to diff
// against): a diff against nothing is not information.
func reportDiff(cmd *cobra.Command, diff report.Diff) {
	if len(diff.Unchanged) == 0 && len(diff.Stale) == 0 {
		return
	}

	_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
		"since the last run into this directory: %d new, %d unchanged, %d no longer reproduced\n",
		len(diff.New), len(diff.Unchanged), len(diff.Stale))
}

// suggestSeverities fills in every finding's suggested CVSS score. It runs
// regardless of --escalate: a finding without escalation capabilities still
// gets the bare-redirect baseline, which is better triage information than
// no severity at all, and one with them gets whatever they raise it to.
func suggestSeverities(findings []model.Finding) []model.Finding {
	for i := range findings {
		severity := report.SuggestSeverity(findings[i].Capabilities)
		findings[i].Severity = &severity
	}

	return findings
}
