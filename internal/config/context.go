package config

import "context"

type contextKey struct{}

// WithConfig stores cfg on ctx for command handlers.
func WithConfig(ctx context.Context, cfg Config) context.Context {
	return context.WithValue(ctx, contextKey{}, cfg)
}

// FromContext returns the Config stored by WithConfig.
func FromContext(ctx context.Context) (Config, bool) {
	cfg, ok := ctx.Value(contextKey{}).(Config)
	return cfg, ok
}
