// Package adapter turns operator corpora into URL strings for the attack engine.
package adapter

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

const maxLine = 1 << 20

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
