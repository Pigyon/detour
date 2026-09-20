// Package lab is detour's in-process accuracy oracle: one fixture per
// technique id, vendor scenarios, decoys, and a loopback landing sink.
package lab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	// DefaultAddr is the listen address used by detour lab and the lab image.
	DefaultAddr = ":1337"

	// AllowedHost is the hostname lab validators treat as trusted.
	AllowedHost = "allowed.lab"

	// SessionCookieName is the cookie the auth-required backUrl endpoint checks.
	SessionCookieName = "lab_session"

	// SessionCookieValue is the value that marks an authenticated lab session.
	SessionCookieValue = "authed"

	clickHost     = "trace.lab"
	clickCampaign = 106519
	maxBlobBytes  = 1 << 20

	// labJWTSignature stands in for a signature the OR-B03 endpoint never checks.
	labJWTSignature = "ZGV0b3VyLWxhYi1zaWduYXR1cmU"
	shutdownWait    = 5 * time.Second
)

// Lab is a vulnerable fixture server. Tests use Handler via httptest;
// detour lab calls Run.
type Lab struct {
	poison *cacheStore
}

// New returns a lab with isolated cache state (for OR-F10).
func New() *Lab {
	return &Lab{poison: newCacheStore()}
}

// Handler serves every catalog route. It is safe for httptest.NewServer.
func (l *Lab) Handler() http.Handler {
	mux := http.NewServeMux()
	registerMeta(mux)
	registerParserDifferentials(mux)
	registerOpaqueDestinations(mux)
	registerClientSide(mux)
	registerBundles(mux)
	registerInfrastructure(mux)
	registerSchemeAbuse(mux)
	l.registerEscalation(mux)
	registerDecoys(mux)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/a11" || strings.HasPrefix(r.URL.Path, "/a11/"):
			handleA11(w, r)
		case r.URL.Path == "/d03" || strings.HasPrefix(r.URL.Path, "/d03/"):
			handleD03(w, r)
		default:
			mux.ServeHTTP(w, r)
		}
	})
}

// Run listens on addr until ctx is cancelled.
func (l *Lab) Run(ctx context.Context, addr string, out io.Writer) error {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	if _, err := fmt.Fprintf(out, "detour lab listening on http://%s\n", ln.Addr().String()); err != nil {
		_ = ln.Close()

		return fmt.Errorf("writing listen banner: %w", err)
	}

	return l.Serve(ctx, ln)
}

// Serve serves the lab on an already-bound listener until ctx is cancelled.
func (l *Lab) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           l.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	errc := make(chan error, 1)

	go func() {
		errc <- srv.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownWait)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutting down lab: %w", err)
		}

		err := <-errc
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("lab server: %w", err)
		}

		return nil
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("lab server: %w", err)
		}

		return nil
	}
}
