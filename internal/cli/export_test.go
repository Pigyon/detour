package cli

// DefaultResumePath exposes defaultResumePath for an external test.
func DefaultResumePath(target, outDir string) string {
	return defaultResumePath(target, outDir)
}

// Slugify exposes slugify for an external test.
func Slugify(s string) string {
	return slugify(s)
}

// TargetOutDir exposes targetOutDir for an external test.
func TargetOutDir(base, target string) string {
	return targetOutDir(base, target)
}
