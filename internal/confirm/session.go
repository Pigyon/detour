package confirm

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/nedlir/detour/internal/scope"
)

const (
	// settleWait is how long a page is given to run its JS and navigate after
	// load. Client-side redirects are the whole point, so the page has to be
	// allowed to act.
	settleWait = 2 * time.Second
	// pollInterval is how often the recorder is checked while settling.
	pollInterval = 50 * time.Millisecond
	// defaultTimeout bounds one page visit end to end.
	defaultTimeout = 20 * time.Second
)

// Result is what the browser did with one target.
type Result struct {
	Target string `json:"target"`
	// FinalURL is the destination the browser intended to reach. It is a
	// captured intent, never a page that was loaded.
	FinalURL   string   `json:"final_url,omitempty"`
	Chain      []Hop    `json:"chain,omitempty"`
	Blocked    []string `json:"blocked,omitempty"`
	Confirmed  bool     `json:"confirmed"`
	Screenshot []byte   `json:"-"`
	HAR        []byte   `json:"-"`
}

// Options configures a confirmation run.
type Options struct {
	Canary     string
	ChromePath string
	Timeout    time.Duration
	Headers    http.Header
	Cookies    []*http.Cookie
	// ArtifactDir turns on screenshot and HAR capture for confirmed results
	// and says where to write them. Empty disables both.
	ArtifactDir string
}

// Confirmer drives a headless browser under the scope guard.
type Confirmer struct {
	guard *scope.Guard
	opts  Options
}

// New builds a confirmer. A nil guard means only the canary is blocked.
func New(guard *scope.Guard, opts Options) *Confirmer {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}

	return &Confirmer{guard: guard, opts: opts}
}

// Visit drives the browser to target and reports where it tried to go.
func (c *Confirmer) Visit(ctx context.Context, target string) (Result, error) {
	path := c.opts.ChromePath
	if path == "" {
		found, err := FindChrome()
		if err != nil {
			return Result{}, err
		}

		path = found
	}

	// A fresh profile per visit: no carried-over storage, no shared cache, and
	// nothing from one target visible to the next.
	profile, err := os.MkdirTemp("", "detour-profile-")
	if err != nil {
		return Result{}, fmt.Errorf("creating browser profile: %w", err)
	}

	defer func() { _ = os.RemoveAll(profile) }()

	return c.run(ctx, path, profile, target)
}

func (c *Confirmer) run(ctx context.Context, chromePath, profile, target string) (Result, error) {
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, allocatorOptions(chromePath, profile)...)
	defer cancelAlloc()

	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx,
		chromedp.WithLogf(debugf),
		chromedp.WithDebugf(debugf),
		// cdproto trails Chrome on newly added protocol enum values and logs a
		// decode error for each one. They are noise on stderr, not failures.
		chromedp.WithErrorf(debugf),
	)
	defer cancelBrowser()

	runCtx, cancelRun := context.WithTimeout(browserCtx, c.opts.Timeout)
	defer cancelRun()

	rec := newRecorder(c.guard, c.opts.Canary)
	c.listen(runCtx, rec)

	if err := chromedp.Run(runCtx, c.setup(target)...); err != nil && !toleratedNavError(err) {
		return Result{}, fmt.Errorf("driving browser to %s: %w", target, err)
	}

	// Capture before settling. Once a renderer-initiated navigation is
	// aborted the renderer will not paint again, so this is the only moment a
	// screenshot can succeed at all.
	early := c.maybeShot(runCtx)

	settle(runCtx, rec)

	return c.finish(rec, target, early), nil
}

func allocatorOptions(chromePath, profile string) []chromedp.ExecAllocatorOption {
	return append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chromePath),
		chromedp.UserDataDir(profile),
		chromedp.Headless,
		chromedp.NoSandbox,
		chromedp.DisableGPU,
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-extensions", true),
	)
}

// setup enables interception before anything navigates, so no request can
// escape while the listeners are still being attached.
func (c *Confirmer) setup(target string) chromedp.Tasks {
	tasks := chromedp.Tasks{
		network.Enable(),
		fetch.Enable(),
	}

	if headers := c.headerMap(target); len(headers) > 0 {
		tasks = append(tasks, network.SetExtraHTTPHeaders(headers))
	}

	if cookies := c.cookieActions(target); cookies != nil {
		tasks = append(tasks, cookies)
	}

	return append(tasks, chromedp.Navigate(target))
}

// listen wires the CDP events that reveal where the browser is going.
func (c *Confirmer) listen(ctx context.Context, rec *recorder) {
	chromedp.ListenTarget(ctx, func(ev any) {
		switch e := ev.(type) {
		case *fetch.EventRequestPaused:
			c.handlePaused(ctx, rec, e)
		case *network.EventRequestWillBeSent:
			if e.RedirectResponse != nil {
				rec.add(e.Request.URL, HopRedirect)
			}
		case *page.EventFrameNavigated:
			if e.Frame != nil {
				rec.add(e.Frame.URL, HopFrame)
			}
		}
	})
}

// handlePaused is the hard stop. Every paused request is either continued or
// aborted; leaving one unanswered would hang the page.
func (c *Confirmer) handlePaused(ctx context.Context, rec *recorder, e *fetch.EventRequestPaused) {
	block := false
	if e.Request != nil {
		block = rec.shouldBlock(e.Request.URL)

		if !block {
			rec.add(e.Request.URL, HopRequest)
		}
	}

	// The event callback must not block, and CDP calls need their own
	// executor bound to this target.
	go func() {
		exec := cdp.WithExecutor(ctx, chromedp.FromContext(ctx).Target)

		if block {
			_ = fetch.FailRequest(e.RequestID, network.ErrorReasonAborted).Do(exec)

			return
		}

		_ = fetch.ContinueRequest(e.RequestID).Do(exec)
	}()
}

// settle waits for client-side navigation, returning as soon as the browser
// commits to leaving for the canary.
func settle(ctx context.Context, rec *recorder) {
	deadline := time.Now().Add(settleWait)

	for time.Now().Before(deadline) {
		if rec.reachedCanary() {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(pollInterval):
		}
	}
}

// maybeShot takes a screenshot only when artifacts were asked for.
func (c *Confirmer) maybeShot(ctx context.Context) []byte {
	if c.opts.ArtifactDir == "" {
		return nil
	}

	return screenshot(ctx)
}

func (c *Confirmer) finish(rec *recorder, target string, early []byte) Result {
	intended, chain, blocked := rec.result()

	out := Result{
		Target:    target,
		FinalURL:  intended,
		Chain:     chain,
		Blocked:   blocked,
		Confirmed: intended != "",
	}

	if out.Confirmed && c.opts.ArtifactDir != "" {
		out.Screenshot = early
		out.HAR = buildHAR(target, chain)
	}

	return out
}

// debugf sends the browser driver's chatter to the debug log so a run's
// stderr stays the operator's, not Chrome's.
func debugf(format string, args ...any) {
	slog.Debug(fmt.Sprintf(format, args...), "component", "browser")
}

// clickThrough loads a controlled page and follows its link, recording where
// the browser is taken.
func (c *Confirmer) clickThrough(ctx context.Context, linkPage string) (Result, error) {
	path, err := c.chromePath()
	if err != nil {
		return Result{}, err
	}

	profile, err := os.MkdirTemp("", "detour-profile-")
	if err != nil {
		return Result{}, fmt.Errorf("creating browser profile: %w", err)
	}

	defer func() { _ = os.RemoveAll(profile) }()

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, allocatorOptions(path, profile)...)
	defer cancelAlloc()

	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx,
		chromedp.WithLogf(debugf),
		chromedp.WithDebugf(debugf),
		chromedp.WithErrorf(debugf),
	)
	defer cancelBrowser()

	runCtx, cancelRun := context.WithTimeout(browserCtx, c.opts.Timeout)
	defer cancelRun()

	rec := newRecorder(c.guard, c.opts.Canary)
	c.listen(runCtx, rec)

	tasks := chromedp.Tasks{
		network.Enable(),
		fetch.Enable(),
		chromedp.Navigate(linkPage),
		chromedp.WaitVisible("#go", chromedp.ByID),
		chromedp.Click("#go", chromedp.ByID),
	}

	if err := chromedp.Run(runCtx, tasks); err != nil && !toleratedNavError(err) {
		return Result{}, fmt.Errorf("driving referer test: %w", err)
	}

	settle(runCtx, rec)

	return c.finish(rec, linkPage, nil), nil
}

// toleratedNavError separates a broken run from a navigation that simply did
// not complete.
//
// Every net::ERR_ is the latter and is evidence rather than failure: the abort
// detour itself caused when a request headed for the canary, a destination
// that does not resolve, a connection refused. The recorder has already
// captured where the browser was going, which is the only thing being asked.
func toleratedNavError(err error) bool {
	if err == nil {
		return true
	}

	return strings.Contains(err.Error(), "net::ERR_")
}
