package adapter

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxSourceBytes = 32 << 20
	maxEntries     = 100_000
)

// Format is a detected corpus kind.
type Format int

const (
	// FormatURLList is one URL per line.
	FormatURLList Format = iota
	// FormatHAR is a HAR 1.2 JSON export.
	FormatHAR
	// FormatBurp is a Burp Suite XML or JSON item export.
	FormatBurp
	// FormatJSONL is newline-delimited JSON with a url field (katana, httpx).
	FormatJSONL
)

// LoadPath reads a corpus from a file, or from stdin when path is "-".
func LoadPath(path string) ([]string, error) {
	var (
		data []byte
		name string
		err  error
	)

	if path == "-" {
		data, err = io.ReadAll(io.LimitReader(os.Stdin, maxSourceBytes+1))
		name = "stdin"
	} else {
		data, err = readLimited(path)
		name = path
	}

	if err != nil {
		return nil, err
	}

	if len(data) > maxSourceBytes {
		return nil, fmt.Errorf("source exceeds %d bytes", maxSourceBytes)
	}

	return LoadBytes(data, name)
}

// LoadBytes dispatches on Detect and extracts http(s) URLs.
func LoadBytes(data []byte, name string) ([]string, error) {
	switch Detect(name, data) {
	case FormatHAR:
		urls, err := ParseHAR(data)
		if err != nil {
			return nil, fmt.Errorf("parsing har: %w", err)
		}

		return urls, nil
	case FormatBurp:
		urls, err := ParseBurp(data)
		if err != nil {
			return nil, fmt.Errorf("parsing burp export: %w", err)
		}

		return urls, nil
	case FormatJSONL:
		urls, err := ParseJSONL(data)
		if err != nil {
			return nil, fmt.Errorf("parsing jsonl: %w", err)
		}

		return urls, nil
	case FormatURLList:
		return Load(bytes.NewReader(data))
	}

	return nil, errors.New("unknown corpus format")
}

// Detect classifies a corpus from its name and a content peek.
func Detect(name string, data []byte) Format {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".har":
		return FormatHAR
	case ".xml":
		return FormatBurp
	case ".jsonl":
		return FormatJSONL
	}

	trim := bytes.TrimSpace(data)
	if len(trim) == 0 {
		return FormatURLList
	}

	switch trim[0] {
	case '<':
		return FormatBurp
	case '{':
		if bytes.Contains(trim, []byte(`"log"`)) && bytes.Contains(trim, []byte(`"entries"`)) {
			return FormatHAR
		}

		if bytes.Contains(trim, []byte(`"items"`)) {
			return FormatBurp
		}

		return FormatJSONL
	}

	if looksJSONL(data) {
		return FormatJSONL
	}

	return FormatURLList
}

func readLimited(path string) ([]byte, error) {
	file, err := os.Open(path) //nolint:gosec // G304: path is the operator-supplied attack source.
	if err != nil {
		return nil, fmt.Errorf("opening source: %w", err)
	}

	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, maxSourceBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading source: %w", err)
	}

	return data, nil
}

func looksJSONL(data []byte) bool {
	line := firstNonEmptyLine(data)
	if line == "" || line[0] != '{' {
		return false
	}

	return bytes.Contains(data, []byte("\n"))
}

func firstNonEmptyLine(data []byte) string {
	for raw := range bytes.SplitSeq(data, []byte("\n")) {
		line := strings.TrimSpace(string(raw))
		if line != "" && !strings.HasPrefix(line, "#") {
			return line
		}
	}

	return ""
}

func acceptHTTPURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}

	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return parsed.Host != ""
	default:
		return false
	}
}

func appendUnique(dst []string, seen map[string]struct{}, raw string) []string {
	if !acceptHTTPURL(raw) {
		return dst
	}

	if _, ok := seen[raw]; ok {
		return dst
	}

	seen[raw] = struct{}{}

	return append(dst, raw)
}

func tooMany(n int) error {
	if n >= maxEntries {
		return fmt.Errorf("source exceeds %d entries", maxEntries)
	}

	return nil
}
