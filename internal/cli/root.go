// Package cli implements the detour command tree.
package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/nedlir/detour/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Execute runs the detour command tree under ctx.
func Execute(ctx context.Context) error {
	return NewRoot().ExecuteContext(ctx)
}

// NewRoot builds a fresh command tree. Tests must call this per case so flag
// state never leaks across Execute calls.
func NewRoot() *cobra.Command {
	v := config.NewViper()

	root := &cobra.Command{
		Use:     "detour",
		Short:   "Open redirect discovery and verification engine",
		Long:    "detour reconstructs where a navigation destination is hiding, how it is validated, and how a browser resolves it.",
		Version: version,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if err := bindFlags(v, cmd); err != nil {
				return err
			}

			cfgFile, err := cmd.Flags().GetString("config")
			if err != nil {
				return fmt.Errorf("reading config flag: %w", err)
			}

			if err := config.LoadFile(v, cfgFile); err != nil {
				return err
			}

			cfg, err := config.Unmarshal(v)
			if err != nil {
				return err
			}

			setupLogger(cfg.LogLevel, cmd.ErrOrStderr())
			ctx := config.WithConfig(cmd.Context(), cfg)
			cmd.SetContext(ctx)
			cmd.Root().SetContext(ctx)

			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	registerPersistentFlags(root)
	root.AddCommand(newVersionCmd())
	root.AddCommand(newScopeCmd())
	root.AddCommand(newLabCmd())
	root.AddCommand(newAttackCmd())
	root.AddCommand(newDecodeCmd())

	return root
}

func registerPersistentFlags(root *cobra.Command) {
	fs := root.PersistentFlags()
	fs.String("config", "", "config file (default $HOME/.detour.yaml)")
	fs.String("log-level", "info", "log level (debug, info, warn, error)")
	fs.String("scope-file", "", "bug bounty scope list; hard boundary on every request")
	fs.String("canary", config.DefaultCanary, "canary host (RFC 6761 .invalid, never contacted)")
	fs.StringArray("header", []string{}, "extra request header (repeatable); in-scope hosts only")
	fs.String("cookie", "", "inline session cookies; in-scope hosts only")
	fs.String("cookies-file", "", "Netscape cookie jar; in-scope hosts only")
	fs.String("proxy", "", "HTTP proxy URL (for example http://127.0.0.1:8080)")
	fs.Float64("rate", 5, "per-host requests per second")
	fs.Int("concurrency", 10, "max concurrent in-flight requests")
	fs.Duration("delay", 0, "additional delay between per-host requests")
	fs.Duration("timeout", 10*time.Second, "per-request timeout")
}

func bindFlags(v *viper.Viper, cmd *cobra.Command) error {
	if err := v.BindPFlags(cmd.Root().PersistentFlags()); err != nil {
		return fmt.Errorf("binding flags: %w", err)
	}

	if err := v.BindPFlags(cmd.Flags()); err != nil {
		return fmt.Errorf("binding flags: %w", err)
	}

	return nil
}

func setupLogger(levelName string, errOut io.Writer) {
	level := slog.LevelInfo

	switch strings.ToLower(levelName) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(errOut, &slog.HandlerOptions{Level: level})))
}
