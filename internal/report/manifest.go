package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nedlir/detour/internal/model"
)

const (
	fileManifest = "MANIFEST.json"
	fileStale    = "STALE.md"
)

// manifestEntry names one finding directory this run produced.
type manifestEntry struct {
	Directory   string `json:"directory"`
	TechniqueID string `json:"technique_id"`
	Fingerprint string `json:"fingerprint"`
}

// manifest is what writeManifest records, so a later run can tell which of
// its own prior directories it is still reproducing.
type manifest struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Findings    []manifestEntry `json:"findings"`
}

// Diff is what changed in findingsDir between the run that is about to write
// and whatever was already there from an earlier one.
type Diff struct {
	// New are directories this run is the first to produce.
	New []string
	// Unchanged are directories a previous run also produced.
	Unchanged []string
	// Stale are directories from a previous run this one did not reproduce.
	Stale []string
}

// diffAndMarkStale compares findings against whatever findingsDir already
// holds, before this run's own directories are written over it, and flags
// every pre-existing directory this run did not reproduce.
//
// It has to run before writeFindingReports, not after: once this run's
// directories exist on disk there is no way to tell a pre-existing one from
// one this run just created. Nothing is deleted. A directory a rerun no
// longer reproduces might mean the defect was fixed, or it might mean this
// run simply did not cover that endpoint; either way the evidence stays, and
// only a marker is added, so the operator decides what it means.
func diffAndMarkStale(findingsDir string, findings []model.Finding) (Diff, error) {
	current := map[string]struct{}{}
	for _, f := range findings {
		current[findingDir(f)] = struct{}{}
	}

	preexisting, err := existingFindingDirs(findingsDir)
	if err != nil {
		return Diff{}, err
	}

	diff := Diff{}

	for name := range current {
		if _, was := preexisting[name]; was {
			diff.Unchanged = append(diff.Unchanged, name)
		} else {
			diff.New = append(diff.New, name)
		}
	}

	for name := range preexisting {
		if _, is := current[name]; !is {
			diff.Stale = append(diff.Stale, name)
		}
	}

	if err := markStale(findingsDir, diff.Stale); err != nil {
		return Diff{}, err
	}

	return diff, nil
}

// existingFindingDirs lists the finding directories already under
// findingsDir, before this run adds its own.
func existingFindingDirs(findingsDir string) (map[string]struct{}, error) {
	entries, err := os.ReadDir(findingsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]struct{}{}, nil
		}

		return nil, fmt.Errorf("reading findings directory: %w", err)
	}

	out := map[string]struct{}{}

	for _, entry := range entries {
		if entry.IsDir() {
			out[entry.Name()] = struct{}{}
		}
	}

	return out, nil
}

// markStale adds a STALE.md marker to each named directory. A directory
// already marked is left alone.
func markStale(findingsDir string, stale []string) error {
	for _, name := range stale {
		marker := filepath.Join(findingsDir, name, fileStale)
		if _, err := os.Stat(marker); err == nil {
			continue
		}

		note := fmt.Sprintf(
			"# Stale\n\nThis finding was not reproduced by the run that completed at %s.\n\n"+
				"That can mean the defect was fixed, or that this run did not cover this endpoint.\n"+
				"The report in this directory is left as it was; nothing here was deleted.\n",
			time.Now().UTC().Format(time.RFC3339))

		if err := writeFile(marker, []byte(note)); err != nil {
			return err
		}
	}

	return nil
}

// writeManifest records which finding directories this run produced, so a
// later run's diff has something to compare against.
func writeManifest(findingsDir string, findings []model.Finding) error {
	entries := make([]manifestEntry, 0, len(findings))
	for _, f := range findings {
		entries = append(entries, manifestEntry{
			Directory:   findingDir(f),
			TechniqueID: f.TechniqueID,
			Fingerprint: Fingerprint(f),
		})
	}

	raw, err := json.MarshalIndent(manifest{GeneratedAt: time.Now().UTC(), Findings: entries}, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding manifest: %w", err)
	}

	raw = append(raw, '\n')

	return writeFile(filepath.Join(findingsDir, fileManifest), raw)
}
