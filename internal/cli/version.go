package cli

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// Set via ldflags at build time.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(
				cmd.OutOrStdout(),
				"detour %s (commit: %s, built: %s)\n",
				version,
				commit,
				date,
			)
			if err != nil {
				return fmt.Errorf("writing version: %w", err)
			}

			if info, ok := debug.ReadBuildInfo(); ok {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "go: %s\n", info.GoVersion); err != nil {
					return fmt.Errorf("writing go version: %w", err)
				}
			}

			return nil
		},
	}
}
