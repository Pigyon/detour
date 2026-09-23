package decode

import (
	"math"
	"strings"
)

const (
	// minTokenLen is the shortest path segment or parameter value worth
	// treating as opaque state.
	minTokenLen = 16
	// minEntropy is the Shannon entropy, in bits per byte, below which a token
	// reads as a word rather than as encoded state.
	minEntropy = 3.0
	// minAlphabetRatio is how much of a token must come from an encoding
	// alphabet before it is worth decoding.
	minAlphabetRatio = 0.9
)

// fileSuffixes are the cosmetic extensions wrappers hang off a blob. The
// KuCoin token wore ".html"; stripping it is what makes it decodable.
var fileSuffixes = []string{
	".html", ".htm", ".php", ".aspx", ".jsp", ".do", ".json", ".txt", ".js",
}

// StripSuffix removes a cosmetic file extension and returns it separately so a
// replay can put it back exactly where it was.
func StripSuffix(token string) (string, string) {
	lower := strings.ToLower(token)

	for _, suffix := range fileSuffixes {
		if strings.HasSuffix(lower, suffix) {
			cut := len(token) - len(suffix)

			return token[:cut], token[cut:]
		}
	}

	return token, ""
}

// maxTokenLen bounds what is treated as an opaque token.
//
// Nothing above this is a navigation envelope, and the cost of pretending
// otherwise is real: every transport is tried over the whole token, each doing
// a decode and a re-encode for the round-trip check, so a 40MB href costs
// hundreds of megabytes. Crawled pages are attacker-influenced input.
const maxTokenLen = 256 << 10

// IsOpaque reports whether token looks like encoded state: long enough, drawn
// from an encoding alphabet, and high-entropy. It is a pre-filter that saves
// work; the decode itself is what decides.
func IsOpaque(token string) bool {
	if len(token) > maxTokenLen {
		return false
	}

	if len(token) < minTokenLen {
		return false
	}

	// A destination already in the clear is not opaque state, and attacking it
	// belongs to the ordinary parameter path rather than to the decoder.
	if looksLikeURL(token) {
		return false
	}

	if alphabetRatio(token) < minAlphabetRatio {
		return false
	}

	return Entropy(token) >= minEntropy
}

// Entropy is the Shannon entropy of s in bits per byte.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}

	counts := [256]int{}
	for i := range len(s) {
		counts[s[i]]++
	}

	total := float64(len(s))
	out := 0.0

	for _, n := range counts {
		if n == 0 {
			continue
		}

		p := float64(n) / total
		out -= p * math.Log2(p)
	}

	return out
}

// alphabetRatio is the share of token drawn from the base64, base32, and hex
// alphabets plus their padding and separators.
func alphabetRatio(token string) float64 {
	if token == "" {
		return 0
	}

	inAlphabet := 0

	for i := range len(token) {
		if isAlphabetByte(token[i]) {
			inAlphabet++
		}
	}

	return float64(inAlphabet) / float64(len(token))
}

func isAlphabetByte(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	case b == '-', b == '_', b == '+', b == '/', b == '=', b == '.':
		return true
	default:
		return false
	}
}
