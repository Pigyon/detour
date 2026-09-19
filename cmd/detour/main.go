// Command detour is the CLI entrypoint for the open redirect engine.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/nedlir/detour/internal/cli"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cli.Execute(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())

		var exitErr *cli.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.Code
		}

		return 1
	}

	return 0
}
