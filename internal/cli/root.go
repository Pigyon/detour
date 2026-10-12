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

	pipeline := &reconFlags{}

	var (
		pipelineHeadless bool
		cancelBudget     context.CancelFunc
	)

	root := &cobra.Command{
		Use:   "detour [target]",
		Short: "Open redirect discovery and verification engine",
		Long: "detour reconstructs where a navigation destination is hiding, how it is validated, and how a " +
			"browser resolves it.\n\nGiven a target, it runs the whole pipeline: surface, harvest, select, " +
			"attack, and with --headless, browser confirmation.",
		Version: version,
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}

			return runPipeline(cmd, args[0], pipeline, pipelineHeadless)
		},
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

			// A budget expiring is handed to the run exactly like Ctrl-C: the
			// context is cancelled, and every stage that already checks
			// ctx.Err() stops and reports what it proved rather than losing
			// the whole scan. The cancel func is released in
			// PersistentPostRunE, after RunE has had the whole run to use it.
			if cfg.Budget > 0 {
				//nolint:gosec // G118: cancelBudget is called in PersistentPostRunE, not discarded
				ctx, cancelBudget = context.WithTimeout(ctx, cfg.Budget)
			}

			cmd.SetContext(ctx)
			cmd.Root().SetContext(ctx)

			return nil
		},
		PersistentPostRunE: func(_ *cobra.Command, _ []string) error {
			if cancelBudget != nil {
				cancelBudget()
			}

			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	registerPersistentFlags(root)
	pipeline.register(root)
	root.Flags().BoolVar(&pipelineHeadless, "headless", false, "prove candidates in a headless browser (needs Chrome)")
	root.AddCommand(newVersionCmd())
	root.AddCommand(newScopeCmd())
	root.AddCommand(newLabCmd())
	root.AddCommand(newAttackCmd())
	root.AddCommand(newDecodeCmd())
	root.AddCommand(newJSCmd())
	root.AddCommand(newConfirmCmd())
	root.AddCommand(newHarvestCmd())
	root.AddCommand(newSurfaceCmd())
	root.AddCommand(newSelectCmd())
	root.AddCommand(newDorksCmd())

	return root
}

func registerPersistentFlags(root *cobra.Command) {
	fs := root.PersistentFlags()
	fs.String("config", "", "config file (default $HOME/.detour.yaml)")
	fs.String("log-level", "info", "log level (debug, info, warn, error)")
	fs.String("scope-file", "", "bug bounty scope list; hard boundary on every request")
	fs.String("redirect-to", config.DefaultRedirectTo,
		"destination payloads try to reach; a redirect that arrives here is the finding (never contacted)")
	fs.String("canary", config.DefaultCanary, "deprecated name for --redirect-to")

	if err := fs.MarkDeprecated("canary", "use --redirect-to"); err != nil {
		panic(err)
	}

	fs.StringArray("header", []string{}, "extra request header (repeatable); in-scope hosts only")
	fs.String("cookie", "", "inline session cookies; in-scope hosts only")
	fs.String("cookies-file", "", "Netscape cookie jar; in-scope hosts only")
	fs.String("proxy", "", "HTTP proxy URL (for example http://127.0.0.1:8080)")
	fs.Float64("rate", 5, "per-host requests per second")
	fs.Int("concurrency", 10, "max concurrent in-flight requests")
	fs.Duration("delay", 0, "additional delay between per-host requests")
	fs.Duration("timeout", 10*time.Second, "per-request timeout")
	fs.Duration("budget", 0,
		"stop the whole run after this long and report what was proved so far (0 means unlimited)")
	fs.Duration("cookies-refresh", 0,
		"re-read --cookies-file on this interval to keep a short-lived session fresh (0 disables)")
	fs.String("auth-check", "",
		"in-scope URL returning authenticated-only content; probed to detect a lost session")
	fs.String("auth-check-expect", "",
		"substring that must appear in --auth-check's response while authenticated")
	fs.Bool("auth-check-required", false,
		"stop the run if the --auth-check probe shows the session is not authenticated")
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
