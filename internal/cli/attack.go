package cli

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nedlir/detour/internal/adapter"
	"github.com/nedlir/detour/internal/attack"
	"github.com/nedlir/detour/internal/client"
	"github.com/nedlir/detour/internal/config"
	"github.com/nedlir/detour/internal/payload"
	"github.com/spf13/cobra"
)

func newAttackCmd() *cobra.Command {
	var keyword string

	cmd := &cobra.Command{
		Use:   "attack source",
		Short: "Probe a URL list or stdin for open redirects",
		Long:  "attack reads a URL list, HAR, Burp export, jsonl stream, or stdin (-) and emits capability-scored findings as JSONL.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAttack(cmd, args[0], keyword)
		},
	}

	cmd.Flags().StringVar(&keyword, "keyword", payload.DefaultKeyword, "injection mark replaced by each payload")

	return cmd
}

func runAttack(cmd *cobra.Command, source, keyword string) error {
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

	findings, err := eng.Run(cmd.Context(), urls)
	if err != nil {
		return err
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
