package confirm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/nedlir/detour/internal/model"
)

// Summary is what a confirmation pass did, so a run can report honestly how
// much of its output was actually proven.
type Summary struct {
	Attempted int `json:"attempted"`
	Confirmed int `json:"confirmed"`
	// Skipped counts findings a browser cannot settle, such as reverse
	// tabnabbing.
	Skipped int `json:"skipped"`
	// Failed counts findings whose visit errored. They stay candidates.
	Failed int `json:"failed"`
}

// Confirm drives every candidate finding in a browser and promotes the ones
// that actually navigate.
//
// A finding is only ever promoted, never demoted or dropped: a browser that
// does not reproduce something is not proof the finding is wrong, only that
// this run did not settle it.
func (c *Confirmer) Confirm(ctx context.Context, findings []model.Finding) ([]model.Finding, Summary, error) {
	if _, err := c.chromePath(); err != nil {
		return findings, Summary{}, err
	}

	out := make([]model.Finding, 0, len(findings))
	summary := Summary{}

	for _, f := range findings {
		promoted, state, err := c.confirmOne(ctx, f)
		if err != nil {
			return nil, summary, err
		}

		summary.apply(state)

		out = append(out, promoted)
	}

	return out, summary, nil
}

// state is what happened to one finding.
type state int

const (
	stateSkipped state = iota
	stateAttempted
	stateConfirmed
	stateFailed
)

func (s *Summary) apply(st state) {
	switch st {
	case stateConfirmed:
		s.Attempted++
		s.Confirmed++
	case stateAttempted:
		s.Attempted++
	case stateFailed:
		s.Attempted++
		s.Failed++
	case stateSkipped:
		s.Skipped++
	}
}

func (c *Confirmer) confirmOne(ctx context.Context, f model.Finding) (model.Finding, state, error) {
	if f.Verdict == model.VerdictConfirmed && f.Capabilities.BrowserConfirmed {
		return f, stateSkipped, nil
	}

	target, ok := ProbeFor(f, c.opts.Canary)
	if !ok {
		return f, stateSkipped, nil
	}

	result, visitErr := c.Visit(ctx, target)
	if visitErr != nil {
		// A visit that failed leaves the finding exactly as it was, and the
		// pass continues. One page that will not load must not sink a run,
		// and it is not evidence about the finding either way.
		return noteFailure(f, visitErr), stateFailed, nil
	}

	if !result.Confirmed {
		f.Evidence = append(f.Evidence, "browser: no navigation to the canary observed")

		return f, stateAttempted, nil
	}

	if err := c.writeArtifacts(f, result); err != nil {
		return f, stateFailed, err
	}

	return promote(f, result), stateConfirmed, nil
}

// noteFailure records that a visit did not happen, without changing the
// finding's verdict.
func noteFailure(f model.Finding, err error) model.Finding {
	f.Evidence = append(f.Evidence, "browser: "+err.Error())

	return f
}

// promote records the browser's verdict on a finding.
func promote(f model.Finding, result Result) model.Finding {
	f.Verdict = model.VerdictConfirmed
	f.Capabilities.BrowserConfirmed = true
	f.Capabilities.RedirectExternal = true

	if hops := navigationHops(result.Chain); hops > f.Capabilities.HopCount {
		f.Capabilities.HopCount = hops
	}

	f.Candidate.Capabilities = f.Capabilities
	f.ProbeURL = result.Target
	f.Evidence = append(f.Evidence,
		"browser_confirmed: "+result.Target,
		"intended destination: "+result.FinalURL,
		fmt.Sprintf("navigation hops: %d", navigationHops(result.Chain)),
	)

	return f
}

// navigationHops counts the redirect steps before the destination.
func navigationHops(chain []Hop) int {
	hops := 0

	for _, hop := range chain {
		if hop.Kind == HopRedirect {
			hops++
		}
	}

	return hops
}

func (c *Confirmer) writeArtifacts(f model.Finding, result Result) error {
	if c.opts.ArtifactDir == "" {
		return nil
	}

	return WriteArtifacts(c.opts.ArtifactDir, artifactKey(f, result.Target), result)
}

// artifactKey names a finding's files stably: same finding, same filenames.
func artifactKey(f model.Finding, target string) string {
	sum := sha256.Sum256([]byte(f.TechniqueID + "\x00" + target))

	return f.TechniqueID + "-" + hex.EncodeToString(sum[:])[:12]
}

func (c *Confirmer) chromePath() (string, error) {
	if c.opts.ChromePath != "" {
		return c.opts.ChromePath, nil
	}

	return FindChrome()
}
