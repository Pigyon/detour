// Package adapter turns operator corpora into URL strings for the attack engine.
package adapter

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

const maxLine = 1 << 20

// LoadPath reads URLs from a file, or from stdin when path is "-".
func LoadPath(path string) ([]string, error) {
	if path == "-" {
		return Load(os.Stdin)
	}

	file, err := os.Open(path) //nolint:gosec // G304: path is the operator-supplied attack source.
	if err != nil {
		return nil, fmt.Errorf("opening source: %w", err)
	}

	defer func() { _ = file.Close() }()

	urls, err := Load(file)
	if err != nil {
		return nil, err
	}

	return urls, nil
}

// Load reads one URL per line. Blank lines and # comments are skipped.
func Load(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLine)

	urls := []string{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		urls = append(urls, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading source: %w", err)
	}

	return urls, nil
}
