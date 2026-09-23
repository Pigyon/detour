package cli

import (
	"errors"
	"fmt"

	"github.com/nedlir/detour/internal/attack"
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

// refuseDestinations adds the second probe's host to the set the guard will
// never contact.
//
// The input_controlled check points its second probe at its own host, and that
// host is no more ours to request than the first. It matters now that the
// second destination can be a real resolving domain: without this, a crawl or
// a URL list containing it would be fetched with the operator's credentials
// attached.
func refuseDestinations(g *scope.Guard, destination string) *scope.Guard {
	g.Refuse(attack.AltCanary(destination))

	return g
}

func guardFromConfig(cfg config.Config) (*scope.Guard, error) {
	destination := cfg.Destination()

	if cfg.ScopeFile == "" {
		return refuseDestinations(scope.New(destination), destination), nil
	}

	g, err := scope.LoadFile(cfg.ScopeFile, destination)
	if err != nil {
		return nil, err
	}

	return refuseDestinations(g, destination), nil
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
