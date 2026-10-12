package confirm

// InjectionCandidates exposes injectionCandidates for an external test.
func InjectionCandidates(chain []Hop) []string {
	return injectionCandidates(chain)
}
