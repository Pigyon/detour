package confirm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

const (
	dirPerm  = 0o750
	filePerm = 0o600
	// harVersion is the HAR spec version detour emits.
	harVersion = "1.2"
)

// screenshotTimeout bounds the capture. It must never consume the visit
// budget: a missing image is a small loss, a hung run is not.
const screenshotTimeout = 2 * time.Second

// screenshot grabs the page as it stands, and is deliberately best effort.
//
// Interception is switched off first, because aborting a navigation leaves
// requests paused and a renderer waiting on one will not paint. The capture
// also avoids the compositor surface, which waits for a frame to be presented.
//
// It still cannot always succeed, and that is inherent rather than a defect.
// The destination is never loaded, by design, so there is nothing to picture
// there. A server-side redirect leaves the previous document intact and
// photographs fine. A page that navigates itself the moment it parses has
// already committed to leaving before any capture can run, and its renderer
// will not paint again once detour refuses the request. Those findings carry
// a HAR and no image.
func screenshot(ctx context.Context) []byte {
	shotCtx, cancel := context.WithTimeout(ctx, screenshotTimeout)
	defer cancel()

	var buf []byte

	err := chromedp.Run(shotCtx, fetch.Disable(), page.StopLoading(), chromedp.ActionFunc(func(ctx context.Context) error {
		shot, err := page.CaptureScreenshot().WithFromSurface(false).Do(ctx)
		if err != nil {
			return fmt.Errorf("capturing screenshot: %w", err)
		}

		buf = shot

		return nil
	}))
	if err != nil {
		return nil
	}

	return buf
}

// har is the minimal HAR 1.2 shape: enough for a reviewer to replay the chain,
// without pretending to be a full network capture.
type har struct {
	Log harLog `json:"log"`
}

type harLog struct {
	Version string     `json:"version"`
	Creator harCreator `json:"creator"`
	Entries []harEntry `json:"entries"`
}

type harCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type harEntry struct {
	StartedDateTime string     `json:"startedDateTime"`
	Request         harRequest `json:"request"`
	Comment         string     `json:"comment"`
}

type harRequest struct {
	Method      string `json:"method"`
	URL         string `json:"url"`
	HTTPVersion string `json:"httpVersion"`
}

// buildHAR renders the observed chain. Blocked hops are kept and labelled:
// the request detour refused to send is the most important line in the file.
func buildHAR(target string, chain []Hop) []byte {
	now := time.Now().UTC().Format(time.RFC3339)

	entries := make([]harEntry, 0, len(chain))

	for _, hop := range chain {
		entries = append(entries, harEntry{
			StartedDateTime: now,
			Request:         harRequest{Method: "GET", URL: hop.URL, HTTPVersion: "HTTP/1.1"},
			Comment:         hop.Kind,
		})
	}

	raw, err := json.MarshalIndent(har{Log: harLog{
		Version: harVersion,
		Creator: harCreator{Name: "detour", Version: harVersion},
		Entries: entries,
	}}, "", "  ")
	if err != nil {
		return nil
	}

	_ = target

	return raw
}

// WriteArtifacts saves a result's screenshot and HAR under dir, named by key.
func WriteArtifacts(dir, key string, result Result) error {
	if dir == "" || (result.Screenshot == nil && result.HAR == nil) {
		return nil
	}

	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("creating artifact directory: %w", err)
	}

	if result.Screenshot != nil {
		path := filepath.Join(dir, key+".png")
		if err := os.WriteFile(path, result.Screenshot, filePerm); err != nil {
			return fmt.Errorf("writing screenshot: %w", err)
		}
	}

	if result.HAR != nil {
		path := filepath.Join(dir, key+".har")
		if err := os.WriteFile(path, result.HAR, filePerm); err != nil {
			return fmt.Errorf("writing har: %w", err)
		}
	}

	return nil
}
