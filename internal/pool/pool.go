// Package pool runs bounded worker groups that exit on context cancel.
package pool

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"

	"golang.org/x/sync/errgroup"
)

// Run calls fn for every item with at most concurrency goroutines.
func Run[T any](ctx context.Context, concurrency int, items []T, fn func(context.Context, T) error) error {
	if concurrency < 1 {
		concurrency = 1
	}

	group, ctx := errgroup.WithContext(ctx)
	group.SetLimit(concurrency)

	for _, item := range items {
		group.Go(func() (err error) {
			defer func() {
				if recovered := recover(); recovered != nil {
					err = fmt.Errorf("worker panic: %v\n%s", recovered, debug.Stack())
				}
			}()

			if err := ctx.Err(); err != nil {
				return err
			}

			return fn(ctx, item)
		})
	}

	if err := group.Wait(); err != nil {
		// A stopped group is the caller stopping, not the pool failing, and
		// pools nest: wrapping it at every level produced the unreadable
		// "worker pool: worker pool: context canceled".
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}

		return fmt.Errorf("worker pool: %w", err)
	}

	return nil
}
