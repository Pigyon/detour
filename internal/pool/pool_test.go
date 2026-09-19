package pool_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nedlir/detour/internal/pool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunProcessesAllItems(t *testing.T) {
	t.Parallel()

	var seen atomic.Int64

	items := []int{1, 2, 3, 4, 5}

	err := pool.Run(context.Background(), 2, items, func(_ context.Context, _ int) error {
		seen.Add(1)
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, int64(len(items)), seen.Load())
}

func TestRunStopsOnCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})

	go func() {
		<-started
		cancel()
	}()

	items := make([]int, 32)
	err := pool.Run(ctx, 1, items, func(ctx context.Context, _ int) error {
		select {
		case started <- struct{}{}:
		default:
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
			return nil
		}
	})
	require.Error(t, err)
}
