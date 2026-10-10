package cli

// DefaultResumePath exposes defaultResumePath for an external test.
func DefaultResumePath(target, outDir string) string {
	return defaultResumePath(target, outDir)
}

// Slugify exposes slugify for an external test.
func Slugify(s string) string {
	return slugify(s)
}
