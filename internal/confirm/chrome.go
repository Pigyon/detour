// Package confirm drives a headless browser to settle what a server-side
// check cannot: whether a browser actually navigates somewhere.
//
// Everything here is opt-in. detour is fully useful with no browser installed,
// and every entry point degrades to a clean no-op when Chrome is absent.
package confirm

import (
	"errors"
	"os"
	"os/exec"
)

// ErrChromeNotFound means no browser binary is installed. It is not a failure
// of the run: callers report it and leave candidates as candidates.
var ErrChromeNotFound = errors.New("confirm: no chrome or chromium binary found")

// chromeCandidates are the binaries to look for, most standard first.
var chromeCandidates = []string{
	"google-chrome",
	"google-chrome-stable",
	"chromium",
	"chromium-browser",
	"chrome",
}

// chromePaths are fixed install locations checked when nothing is on PATH.
var chromePaths = []string{
	"/opt/google/chrome/chrome",
	"/usr/bin/chromium",
	"/usr/bin/chromium-browser",
	"/snap/bin/chromium",
	"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	"/Applications/Chromium.app/Contents/MacOS/Chromium",
}

// FindChrome returns a usable browser binary, honoring DETOUR_CHROME first so
// an operator can point at a specific build.
func FindChrome() (string, error) {
	if custom := os.Getenv("DETOUR_CHROME"); custom != "" {
		if isExecutable(custom) {
			return custom, nil
		}

		return "", ErrChromeNotFound
	}

	for _, name := range chromeCandidates {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}

	for _, path := range chromePaths {
		if isExecutable(path) {
			return path, nil
		}
	}

	return "", ErrChromeNotFound
}

// Available reports whether headless confirmation can run on this machine.
// Tests use it to skip rather than fail.
func Available() bool {
	_, err := FindChrome()

	return err == nil
}

func isExecutable(path string) bool {
	// G703: path is either a fixed entry in chromePaths or the operator's own
	// DETOUR_CHROME override. Nothing attacker-controlled reaches here.
	info, err := os.Stat(path) //nolint:gosec // G703: fixed list or operator override.
	if err != nil || info.IsDir() {
		return false
	}

	return info.Mode()&0o111 != 0
}
