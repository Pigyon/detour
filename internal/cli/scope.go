package cli

import (
	"errors"
	"fmt"

	"github.com/nedlir/detour/internal/config"
	"github.com/nedlir/detour/internal/scope"
	"github.com/spf13/cobra"
)

func newScopeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scope",
		Short: "Inspect the scope guard",
	}
	cmd.AddCommand(newScopeTestCmd())

	return cmd
}

func newScopeTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test url [url...]",
		Short: "Print whether each URL is in scope",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, ok := config.FromContext(cmd.Context())
			if !ok {
				return errors.New("config not loaded")
			}

			guard, err := guardFromConfig(cfg)
			if err != nil {
				return err
			}

			var failed bool

			for _, raw := range args {
				verdict, checkErr := classify(guard, raw)
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\n", verdict, raw); err != nil {
					return fmt.Errorf("writing verdict: %w", err)
				}

				if checkErr != nil {
					failed = true
				}
			}

			if failed {
				return &ExitError{Code: 1, Err: errors.New("one or more urls are out of scope")}
			}

			return nil
		},
	}
}

func guardFromConfig(cfg config.Config) (*scope.Guard, error) {
	if cfg.ScopeFile == "" {
		return scope.New(cfg.Canary), nil
	}

	g, err := scope.LoadFile(cfg.ScopeFile, cfg.Canary)
	if err != nil {
		return nil, err
	}

	return g, nil
}

func classify(guard *scope.Guard, raw string) (string, error) {
	err := guard.CheckURL(raw)
	switch {
	case err == nil:
		return "IN-SCOPE", nil
	case errors.Is(err, scope.ErrCanary):
		return "CANARY", err
	case errors.Is(err, scope.ErrOutOfScope):
		return "OUT-OF-SCOPE", err
	default:
		return "ERROR", err
	}
}
