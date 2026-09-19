// Package cli implements the detour command tree.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const envPrefix = "DETOUR"

// Execute runs the detour command tree under ctx.
func Execute(ctx context.Context) error {
	cmd := NewRoot()
	cmd.SetContext(ctx)

	return cmd.Execute()
}

// NewRoot builds a fresh command tree. Tests must call this per case so flag
// state never leaks across Execute calls.
func NewRoot() *cobra.Command {
	v := viper.New()

	root := &cobra.Command{
		Use:   "detour",
		Short: "Open redirect discovery and verification engine",
		Long:  "detour reconstructs where a navigation destination is hiding, how it is validated, and how a browser resolves it.",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if err := bindFlags(v, cmd); err != nil {
				return err
			}

			if err := loadConfig(v, cmd); err != nil {
				return err
			}

			setupLogger(v, cmd.ErrOrStderr())

			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().String("config", "", "config file (default $HOME/.detour.yaml)")
	root.PersistentFlags().String("log-level", "info", "log level (debug, info, warn, error)")

	root.AddCommand(newVersionCmd())

	return root
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

func loadConfig(v *viper.Viper, cmd *cobra.Command) error {
	cfgFile, err := cmd.Flags().GetString("config")
	if err != nil {
		return fmt.Errorf("reading config flag: %w", err)
	}

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return fmt.Errorf("finding home directory: %w", homeErr)
		}

		v.AddConfigPath(home)
		v.AddConfigPath(".")
		v.SetConfigName(".detour")
		v.SetConfigType("yaml")
	}

	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			return fmt.Errorf("reading config: %w", err)
		}
	}

	return nil
}

func setupLogger(v *viper.Viper, errOut io.Writer) {
	level := slog.LevelInfo

	switch strings.ToLower(v.GetString("log-level")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(errOut, &slog.HandlerOptions{Level: level})))
}
