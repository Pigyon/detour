package report_test

import (
	"testing"

	"github.com/nedlir/detour/internal/lab"
	"github.com/nedlir/detour/internal/report"
	"github.com/stretchr/testify/assert"
)

// TestRemediationCoversEveryTechnique keeps a report from telling a developer
// a technique is broken without saying what to change.
func TestRemediationCoversEveryTechnique(t *testing.T) {
	t.Parallel()

	for _, id := range lab.TechniqueIDs {
		assert.NotEqual(t, "Validate the destination against an exact-match allowlist of hosts you control.",
			report.Remediation(id), "%s has no specific remediation", id)
	}
}
