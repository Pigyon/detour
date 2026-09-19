// Package pool runs bounded worker groups that exit on context cancel.
package pool

import (
	"context"
	"fmt"

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
					err = fmt.Errorf("worker panic: %v", recovered)
				}
			}()

			if err := ctx.Err(); err != nil {
				return err
			}

			return fn(ctx, item)
		})
	}

	if err := group.Wait(); err != nil {
		return fmt.Errorf("worker pool: %w", err)
	}

	return nil
}
