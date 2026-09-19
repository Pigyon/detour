// Package checkpoint is an append-only attempt log used by detour attack --resume.
package checkpoint

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// SchemaVersion is written on every checkpoint record.
const SchemaVersion = "1"

const maxLine = 1 << 20

// Record is one attempted candidate + payload and its verdict.
type Record struct {
	SchemaVersion string `json:"schema_version"`
	Source        string `json:"source"`
	Payload       string `json:"payload"`
	Technique     string `json:"technique"`
	Hit           bool   `json:"hit"`
}

// Store is a crash-safe, append-only jsonl checkpoint.
type Store struct {
	mu   sync.Mutex
	file *os.File
	seen map[string]struct{}
}

// Open loads existing records from path and prepares it for appends.
func Open(path string) (*Store, error) {
	seen, err := loadPath(path)
	if err != nil {
		return nil, err
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G304: path is the operator-supplied --resume file.
	if err != nil {
		return nil, fmt.Errorf("opening checkpoint: %w", err)
	}

	return &Store{file: file, seen: seen}, nil
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

// Seen reports whether source+payload+technique was already attempted.
func (s *Store) Seen(source, payload, technique string) bool {
	if s == nil {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, ok := s.seen[key(source, payload, technique)]

	return ok
}

// RecordAttempt appends a verdict unless that attempt is already stored.
func (s *Store) RecordAttempt(source, payload, technique string, hit bool) error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	k := key(source, payload, technique)
	if _, ok := s.seen[k]; ok {
		return nil
	}

	rec := Record{
		SchemaVersion: SchemaVersion,
		Source:        source,
		Payload:       payload,
		Technique:     technique,
		Hit:           hit,
	}

	if err := json.NewEncoder(s.file).Encode(rec); err != nil {
		return fmt.Errorf("writing checkpoint: %w", err)
	}

	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("syncing checkpoint: %w", err)
	}

	s.seen[k] = struct{}{}

	return nil
}

// Load parses records from r. Truncated or invalid lines are skipped.
func Load(r io.Reader) map[string]struct{} {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLine)

	seen := map[string]struct{}{}

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}

		if rec.Source == "" && rec.Payload == "" && rec.Technique == "" {
			continue
		}

		seen[key(rec.Source, rec.Payload, rec.Technique)] = struct{}{}
	}

	return seen
}

func loadPath(path string) (map[string]struct{}, error) {
	file, err := os.Open(path) //nolint:gosec // G304: path is the operator-supplied --resume file.
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]struct{}{}, nil
		}

		return nil, fmt.Errorf("reading checkpoint: %w", err)
	}

	defer func() { _ = file.Close() }()

	return Load(file), nil
}

func key(source, payload, technique string) string {
	return source + "\x00" + payload + "\x00" + technique
}
