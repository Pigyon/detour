package cli

import (
	"encoding/json"
	"errors"
	"fmt"

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
		keyword string
		filter  string
		outDir  string
		resume  string
	)

	cmd := &cobra.Command{
		Use:   "attack source",
		Short: "Probe a URL list or stdin for open redirects",
		Long:  "attack reads a URL list, HAR, Burp export, jsonl stream, or stdin (-) and emits capability-scored findings as JSONL.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAttack(cmd, args[0], keyword, filter, outDir, resume)
		},
	}

	cmd.Flags().StringVar(&keyword, "keyword", payload.DefaultKeyword, "injection mark replaced by each payload")
	cmd.Flags().StringVar(&filter, "filter", "", "comma-separated mechanisms to report (header,js,meta,refresh,crlf,blob,query)")
	cmd.Flags().StringVar(&outDir, "out", "", "write findings.jsonl, findings.json, and report.md to this directory")
	cmd.Flags().StringVar(&resume, "resume", "", "append-only checkpoint file; skip completed attempts")

	return cmd
}

func runAttack(cmd *cobra.Command, source, keyword, filter, outDir, resume string) error {
	cfg, ok := config.FromContext(cmd.Context())
	if !ok {
		return errors.New("config not loaded")
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

	eng := attack.New(c, cfg.Canary, keyword, cfg.Concurrency, nil)

	closer, err := attachCheckpoint(eng, resume)
	if err != nil {
		return err
	}

	defer closer()

	findings, err := eng.Run(cmd.Context(), urls)
	if err != nil {
		return err
	}

	return writeAttackOutput(cmd, findings, filter, outDir)
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

func writeAttackOutput(cmd *cobra.Command, findings []model.Finding, filter, outDir string) error {
	allow, err := report.ParseFilter(filter)
	if err != nil {
		return err
	}

	findings = report.Apply(findings, allow)

	if outDir != "" {
		if err := report.Write(outDir, findings); err != nil {
			return err
		}
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	for _, f := range findings {
		if err := enc.Encode(f); err != nil {
			return fmt.Errorf("writing finding: %w", err)
		}
	}

	_, err = fmt.Fprintf(cmd.ErrOrStderr(), "%d findings\n", len(findings))

	return err
}
