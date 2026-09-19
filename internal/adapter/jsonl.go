package adapter

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

type jsonlRow struct {
	URL     string `json:"url"`
	Input   string `json:"input"`
	Request struct {
		URL      string `json:"url"`
		Endpoint string `json:"endpoint"`
	} `json:"request"`
}

// ParseJSONL extracts URLs from newline-delimited JSON (katana, httpx).
func ParseJSONL(data []byte) ([]string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), maxLine)

	urls := []string{}
	seen := map[string]struct{}{}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		raw, ok, err := jsonlURL(line)
		if err != nil {
			continue
		}

		if !ok {
			continue
		}

		if err := tooMany(len(urls)); err != nil {
			return nil, err
		}

		urls = appendUnique(urls, seen, raw)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading jsonl: %w", err)
	}

	return urls, nil
}

func jsonlURL(line string) (string, bool, error) {
	var row jsonlRow
	if err := json.Unmarshal([]byte(line), &row); err != nil {
		return "", false, err
	}

	for _, candidate := range []string{row.URL, row.Input, row.Request.URL, row.Request.Endpoint} {
		if candidate != "" {
			return candidate, true, nil
		}
	}

	return "", false, nil
}
