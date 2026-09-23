// Package checkpoint is an append-only attempt log used by detour attack --resume.
package checkpoint

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/nedlir/detour/internal/model"
)

// SchemaVersion is written on every checkpoint record.
//
// Version 2 keys an attempt by the request that was actually sent. Version 1
// keyed it by source, expanded payload and technique, which two different
// probes of the same source can share: one envelope carrying the destination
// in two fields produces two attempts with the same three values. The first
// one's miss then suppressed the second one's hit, and a run with --resume
// quietly reported one finding fewer than the same scan without it.
//
// Records written under another version are ignored rather than adapted. A
// v1 record has no attempt to key on, and guessing one would resurrect the
// bug this version exists to fix.
const SchemaVersion = "2"

const maxLine = 1 << 20

// Record is one attempt and its verdict.
//
// Attempt is the request that was sent, which is what makes two attempts
// distinguishable. A hit carries the finding it produced: without it a
// resumed run skips the work and has nothing to show for it, so an
// interrupted scan comes back reporting zero and overwrites the report that
// had the answers.
type Record struct {
	SchemaVersion string         `json:"schema_version"`
	Source        string         `json:"source"`
	Attempt       string         `json:"attempt"`
	Technique     string         `json:"technique"`
	Hit           bool           `json:"hit"`
	Finding       *model.Finding `json:"finding,omitempty"`
}

// Store is a crash-safe, append-only jsonl checkpoint.
type Store struct {
	mu   sync.Mutex
	file *os.File
	seen map[string]struct{}
	// done holds the findings earlier runs already proved, keyed the same way
	// as seen, so a resumed run can hand them back instead of losing them.
	done map[string]model.Finding
}

// Open loads existing records from path and prepares it for appends.
func Open(path string) (*Store, error) {
	seen, done, err := loadPath(path)
	if err != nil {
		return nil, err
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G304: path is the operator-supplied --resume file.
	if err != nil {
		return nil, fmt.Errorf("opening checkpoint: %w", err)
	}

	return &Store{file: file, seen: seen, done: done}, nil
}

// Recover returns the finding an earlier run recorded for this attempt.
func (s *Store) Recover(source, attempt, technique string) (model.Finding, bool) {
	if s == nil {
		return model.Finding{}, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.done[key(source, attempt, technique)]

	return f, ok
}

// Close flushes and closes the checkpoint file.
func (s *Store) Close() error {
	if s == nil || s.file == nil {
		return nil
	}

	if err := s.file.Close(); err != nil {
		return fmt.Errorf("closing checkpoint: %w", err)
	}

	s.file = nil

	return nil
}

// Seen reports whether this attempt was already made.
func (s *Store) Seen(source, attempt, technique string) bool {
	if s == nil {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, ok := s.seen[key(source, attempt, technique)]

	return ok
}

// RecordAttempt appends a verdict unless that attempt is already stored.
func (s *Store) RecordAttempt(source, attempt, technique string, hit bool) error {
	return s.record(source, attempt, technique, hit, nil)
}

// RecordHit appends a verdict together with the finding it produced.
func (s *Store) RecordHit(source, attempt, technique string, f model.Finding) error {
	return s.record(source, attempt, technique, true, &f)
}

func (s *Store) record(source, attempt, technique string, hit bool, f *model.Finding) error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	k := key(source, attempt, technique)
	if _, ok := s.seen[k]; ok {
		return nil
	}

	rec := Record{
		SchemaVersion: SchemaVersion,
		Source:        source,
		Attempt:       attempt,
		Technique:     technique,
		Hit:           hit,
		Finding:       f,
	}

	if err := json.NewEncoder(s.file).Encode(rec); err != nil {
		return fmt.Errorf("writing checkpoint: %w", err)
	}

	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("syncing checkpoint: %w", err)
	}

	s.seen[k] = struct{}{}

	if f != nil {
		s.done[k] = *f
	}

	return nil
}

// Load parses records from r, returning the attempts already made and the
// findings they produced. Truncated or invalid lines are skipped.
func Load(r io.Reader) (seen map[string]struct{}, done map[string]model.Finding) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLine)

	seen = map[string]struct{}{}
	done = map[string]model.Finding{}

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}

		if rec.SchemaVersion != SchemaVersion {
			continue
		}

		if rec.Source == "" && rec.Attempt == "" && rec.Technique == "" {
			continue
		}

		k := key(rec.Source, rec.Attempt, rec.Technique)
		seen[k] = struct{}{}

		if rec.Finding != nil {
			done[k] = *rec.Finding
		}
	}

	return seen, done
}

func loadPath(path string) (map[string]struct{}, map[string]model.Finding, error) {
	file, err := os.Open(path) //nolint:gosec // G304: path is the operator-supplied --resume file.
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]struct{}{}, map[string]model.Finding{}, nil
		}

		return nil, nil, fmt.Errorf("reading checkpoint: %w", err)
	}

	defer func() { _ = file.Close() }()

	seen, done := Load(file)

	return seen, done, nil
}

func key(source, attempt, technique string) string {
	return source + "\x00" + attempt + "\x00" + technique
}
