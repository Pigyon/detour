package report

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/nedlir/detour/internal/model"
)

// fileUntested is where a run lists what it could not test: probes a WAF or
// edge refused, and sources behind a login wall. Neither is clean, and a
// report that only lists findings makes both look exactly like a target with
// nothing to find.
const fileUntested = "untested.json"

// Untested is the content of untested.json.
type Untested struct {
	// Blocked is the exact number of refused probes; BlockedProbes may be a
	// bounded subset of them.
	Blocked       int                  `json:"blocked"`
	BlockedBy     map[string]int       `json:"blocked_by,omitempty"`
	BlockedProbes []model.BlockedProbe `json:"blocked_probes,omitempty"`
	AuthWalls     []model.AuthWall     `json:"auth_walls,omitempty"`
}

// Empty reports whether there is nothing to write.
func (u Untested) Empty() bool {
	return u.Blocked == 0 && len(u.AuthWalls) == 0
}

// WriteUntested writes untested.json into dir. Nothing untested writes
// nothing, for the same reason WriteOpaqueEnvelopes stays silent.
func WriteUntested(dir string, u Untested) error {
	if u.Empty() {
		return nil
	}

	raw, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding untested: %w", err)
	}

	raw = append(raw, '\n')

	return writeFile(filepath.Join(dir, fileUntested), raw)
}
