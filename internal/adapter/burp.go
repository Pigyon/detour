package adapter

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
)

type burpXML struct {
	XMLName xml.Name   `xml:"items"`
	Items   []burpItem `xml:"item"`
}

type burpItem struct {
	URL string `xml:"url"`
}

type burpJSON struct {
	Items []burpJSONItem `json:"items"`
}

type burpJSONItem struct {
	URL string `json:"url"`
}

// ParseBurp extracts request URLs from a Burp XML or JSON item export.
func ParseBurp(data []byte) ([]string, error) {
	trim := bytes.TrimSpace(data)
	if len(trim) == 0 {
		return []string{}, nil
	}

	if trim[0] == '<' {
		return parseBurpXML(trim)
	}

	return parseBurpJSON(trim)
}

func parseBurpXML(data []byte) ([]string, error) {
	var doc burpXML
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decoding burp xml: %w", err)
	}

	urls := make([]string, 0, len(doc.Items))
	seen := map[string]struct{}{}

	for _, item := range doc.Items {
		if err := tooMany(len(urls)); err != nil {
			return nil, err
		}

		urls = appendUnique(urls, seen, item.URL)
	}

	return urls, nil
}

func parseBurpJSON(data []byte) ([]string, error) {
	var doc burpJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decoding burp json: %w", err)
	}

	urls := make([]string, 0, len(doc.Items))
	seen := map[string]struct{}{}

	for _, item := range doc.Items {
		if err := tooMany(len(urls)); err != nil {
			return nil, err
		}

		urls = appendUnique(urls, seen, item.URL)
	}

	return urls, nil
}
