package cli

import (
	"github.com/nedlir/detour/internal/lab"
	"github.com/spf13/cobra"
)

func newLabCmd() *cobra.Command {
	var (
		addr string
		list bool
	)

	cmd := &cobra.Command{
		Use:   "lab",
		Short: "Run the local vulnerable test server",
		Long:  "lab serves one fixture per technique id, vendor scenarios, decoys, and a loopback landing sink.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if list {
				return lab.WriteCatalog(cmd.OutOrStdout())
			}

			return lab.New().Run(cmd.Context(), addr, cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&addr, "addr", lab.DefaultAddr, "listen address")
	cmd.Flags().BoolVar(&list, "list", false, "print endpoints as JSON and exit")

	return cmd
}
