package adapter

import (
	"encoding/json"
	"fmt"
)

type harFile struct {
	Log harLog `json:"log"`
}

type harLog struct {
	Entries []harEntry `json:"entries"`
}

type harEntry struct {
	Request harRequest `json:"request"`
}

type harRequest struct {
	URL string `json:"url"`
}

// ParseHAR extracts request URLs from a HAR 1.2 document.
func ParseHAR(data []byte) ([]string, error) {
	var doc harFile
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decoding har json: %w", err)
	}

	urls := make([]string, 0, len(doc.Log.Entries))
	seen := map[string]struct{}{}

	for _, entry := range doc.Log.Entries {
		if err := tooMany(len(urls)); err != nil {
			return nil, err
		}

		urls = appendUnique(urls, seen, entry.Request.URL)
	}

	return urls, nil
}
