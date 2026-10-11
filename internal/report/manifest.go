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

// writeManifestAndMarkStale records which finding directories this run
// produced, and flags any directory already under findingsDir from an
// earlier run that this run did not reproduce.
//
// Nothing is deleted. A directory a rerun no longer reproduces might mean the
// defect was fixed, or it might mean this run simply did not cover that
// endpoint; either way the evidence stays, and only a marker is added, so the
// operator decides what it means rather than losing the report that proved
// it.
func writeManifestAndMarkStale(findingsDir string, findings []model.Finding) error {
	entries := make([]manifestEntry, 0, len(findings))
	current := map[string]struct{}{}

	for _, f := range findings {
		name := findingDir(f)
		entries = append(entries, manifestEntry{
			Directory:   name,
			TechniqueID: f.TechniqueID,
			Fingerprint: Fingerprint(f),
		})
		current[name] = struct{}{}
	}

	if err := markStale(findingsDir, current); err != nil {
		return err
	}

	raw, err := json.MarshalIndent(manifest{GeneratedAt: time.Now().UTC(), Findings: entries}, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding manifest: %w", err)
	}

	raw = append(raw, '\n')

	return writeFile(filepath.Join(findingsDir, fileManifest), raw)
}

// markStale adds a STALE.md marker to every existing finding directory not
// named in current. A directory already marked, or already named this run,
// is left alone.
func markStale(findingsDir string, current map[string]struct{}) error {
	entries, err := os.ReadDir(findingsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return fmt.Errorf("reading findings directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		if _, reproduced := current[entry.Name()]; reproduced {
			continue
		}

		marker := filepath.Join(findingsDir, entry.Name(), fileStale)
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
