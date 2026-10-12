package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/nedlir/detour/internal/attack"
	"github.com/nedlir/detour/internal/config"
	"github.com/nedlir/detour/internal/hackerone"
	"github.com/nedlir/detour/internal/scope"
	"github.com/spf13/cobra"
)

func newScopeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scope",
		Short: "Inspect the scope guard",
	}
	cmd.AddCommand(newScopeTestCmd())
	cmd.AddCommand(newScopeImportCmd())

	return cmd
}

// hackeroneTokenEnv is where the operator's own HackerOne API token lives.
// Never a flag: a flag value sits in shell history and in this process's
// argv, which any other user on the box can read from /proc.
const hackeroneTokenEnv = "DETOUR_HACKERONE_TOKEN"

func newScopeImportCmd() *cobra.Command {
	var (
		handle   string
		username string
		outPath  string
	)

	cmd := &cobra.Command{
		Use:   "import",
		Short: "Build a scope file from a HackerOne program's structured scope",
		Long: "import reads a program's structured scope through the authenticated hacker API and writes " +
			"it as a scope file --scope-file already understands: one web asset per line, submittable " +
			"assets only. The token comes from " + hackeroneTokenEnv + ", never a flag.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if handle == "" {
				return errors.New("--hackerone is required")
			}

			if username == "" {
				return errors.New("--username is required")
			}

			token := os.Getenv(hackeroneTokenEnv)
			if token == "" {
				return fmt.Errorf("%s is not set", hackeroneTokenEnv)
			}

			assets, err := hackerone.FetchScope(cmd.Context(), handle, username, token)
			if err != nil {
				return err
			}

			lines := hackerone.ScopeLines(assets)
			if len(lines) == 0 {
				return fmt.Errorf("%s: no submittable web assets in scope", handle)
			}

			out := strings.Join(lines, "\n") + "\n"

			if outPath == "" {
				_, err := fmt.Fprint(cmd.OutOrStdout(), out)

				return err
			}

			//nolint:gosec // G703: outPath is the operator-supplied --out.
			if err := os.WriteFile(outPath, []byte(out), 0o600); err != nil {
				return fmt.Errorf("writing scope file: %w", err)
			}

			_, err = fmt.Fprintf(cmd.ErrOrStderr(), "%d assets written to %s\n", len(lines), outPath)

			return err
		},
	}

	cmd.Flags().StringVar(&handle, "hackerone", "", "HackerOne program handle")
	cmd.Flags().StringVar(&username, "username", "", "your HackerOne username")
	cmd.Flags().StringVar(&outPath, "out", "", "write the scope file here instead of stdout")

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
