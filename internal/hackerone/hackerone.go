// Package hackerone reads a program's structured scope from HackerOne's own
// hacker API, so a scope file does not have to be hand-built from it.
package hackerone

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// APIBase is HackerOne's hacker API. A var, not a const, so a test can point
// it at a local server instead of the real one.
var APIBase = "https://api.hackerone.com/v1/hackers/programs"

const requestTimeout = 30 * time.Second

// webAssetTypes are the structured-scope types a URL-based scanner can use.
// Mobile store listings, hardware, source code, and model weights have no
// web surface to point detour at.
var webAssetTypes = map[string]struct{}{
	"URL":      {},
	"WILDCARD": {},
}

// Asset is one structured-scope entry, trimmed to what a scope file needs.
type Asset struct {
	Identifier            string `json:"asset_identifier"`
	Type                  string `json:"asset_type"`
	EligibleForSubmission bool   `json:"eligible_for_submission"`
	EligibleForBounty     bool   `json:"eligible_for_bounty"`
}

// programResponse is the subset of the hacker API's program response this
// package reads. The API has no envelope on this endpoint: attributes and
// relationships sit at the top level, not under a "data" key.
type programResponse struct {
	Relationships struct {
		StructuredScopes struct {
			Data []struct {
				Attributes Asset `json:"attributes"`
			} `json:"data"`
		} `json:"structured_scopes"`
	} `json:"relationships"`
}

// ErrUnauthorized means the username or token HackerOne was given is wrong.
var ErrUnauthorized = errors.New("hackerone: unauthorized; check the username and token")

// FetchScope reads handle's structured scope. username and token are the
// operator's own HackerOne credentials: this is the authenticated hacker
// API, not the public bounty-targets-data dump, and sees private programs
// the operator has access to.
func FetchScope(ctx context.Context, handle, username, token string) ([]Asset, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, APIBase+"/"+handle, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	req.SetBasicAuth(username, token)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", handle, err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrUnauthorized
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hackerone: %s answered %d", handle, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var parsed programResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", handle, err)
	}

	out := make([]Asset, 0, len(parsed.Relationships.StructuredScopes.Data))
	for _, entry := range parsed.Relationships.StructuredScopes.Data {
		out = append(out, entry.Attributes)
	}

	return out, nil
}

// ScopeLines turns assets into lines scope.Parse already understands: each
// web asset's identifier, one per line, passed through verbatim. HackerOne's
// own asset_identifier is already either a bare host, a wildcard, or a full
// URL, which is exactly the format a scope file expects.
//
// Only assets eligible for submission are included: that is the program's
// own hard boundary on what may be tested at all, bounty-eligible or not.
func ScopeLines(assets []Asset) []string {
	out := []string{}

	for _, a := range assets {
		if !a.EligibleForSubmission {
			continue
		}

		if _, isWeb := webAssetTypes[a.Type]; !isWeb {
			continue
		}

		identifier := strings.TrimSpace(a.Identifier)
		if identifier == "" {
			continue
		}

		out = append(out, identifier)
	}

	return out
}
