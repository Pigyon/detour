package confirm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// refererShutdown bounds the wait when tearing the harness server down.
const refererShutdown = 2 * time.Second

// RefererResult is what the referer test observed.
type RefererResult struct {
	Target string `json:"target"`
	// LinkPage is the controlled page the click came from.
	LinkPage string `json:"link_page"`
	// Returned is true when the target navigated the browser back to the
	// referring origin, which is what OR-D05 looks like.
	Returned  bool  `json:"returned"`
	Confirmed bool  `json:"confirmed"`
	Chain     []Hop `json:"chain,omitempty"`
}

// RefererTest is the automated form of the manual test: host a page, click a
// link to the target, and watch where the browser ends up.
//
// It is the only way to settle an endpoint that redirects with no parameter
// at all, because the input is the Referer header the browser sends on its
// own. Nothing a request-forging client sends can prove it.
func (c *Confirmer) RefererTest(ctx context.Context, target string) (RefererResult, error) {
	if _, err := c.chromePath(); err != nil {
		return RefererResult{}, err
	}

	nonce, err := newNonce()
	if err != nil {
		return RefererResult{}, err
	}

	harness, err := startRefererHarness(ctx, nonce, target)
	if err != nil {
		return RefererResult{}, err
	}

	defer harness.stop()

	result, err := c.clickThrough(ctx, harness.linkURL())
	if err != nil {
		return RefererResult{}, err
	}

	returned := harness.returned()

	return RefererResult{
		Target:    target,
		LinkPage:  harness.linkURL(),
		Returned:  returned,
		Confirmed: returned || result.Confirmed,
		Chain:     result.Chain,
	}, nil
}

// refererHarness serves the controlled linking page and notices when the
// target sends the browser back.
type refererHarness struct {
	server *http.Server
	addr   string
	nonce  string
	// link counts loads of the page holding the link.
	link atomic.Int64
	// back counts hits on any other path. Chrome trims a cross-origin Referer
	// to the bare origin, so a target that redirects to it lands on "/",
	// never on the nonce path.
	back atomic.Int64
}

// returned reports whether the target navigated the browser back to the
// referring origin.
func (h *refererHarness) returned() bool {
	return h.back.Load() > 0 || h.link.Load() > 1
}

func startRefererHarness(ctx context.Context, nonce, target string) (*refererHarness, error) {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("starting referer harness: %w", err)
	}

	h := &refererHarness{addr: ln.Addr().String(), nonce: nonce}

	mux := http.NewServeMux()
	mux.HandleFunc("/"+nonce, func(w http.ResponseWriter, _ *http.Request) {
		h.link.Add(1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w,
			`<!doctype html><title>detour</title><a id="go" href="%s">go</a>`+"\n",
			html.EscapeString(target),
		)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if isNavigation(r) {
			h.back.Add(1)
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprint(w, "returned\n")
	})

	h.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	go func() { _ = h.server.Serve(ln) }()

	return h, nil
}

func (h *refererHarness) linkURL() string {
	return "http://" + h.addr + "/" + h.nonce
}

func (h *refererHarness) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), refererShutdown)
	defer cancel()

	_ = h.server.Shutdown(ctx)
}

// isNavigation separates the browser being sent back here from the noise it
// fetches on its own. Displaying the link page makes Chrome ask for
// /favicon.ico, and counting that would confirm every target.
func isNavigation(r *http.Request) bool {
	if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "" {
		return dest == "document"
	}

	return r.URL.Path != "/favicon.ico"
}

func newNonce() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating harness nonce: %w", err)
	}

	return "detour-" + hex.EncodeToString(buf), nil
}
