package decode

import (
	"regexp"
	"strings"

	"github.com/nedlir/detour/internal/model"
)

var (
	hexDigest  = regexp.MustCompile(`^[0-9a-fA-F]{16,64}$`)
	uuidValue  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	emailValue = regexp.MustCompile(`[\w.+-]+@[\w.-]+\.\w+`)
	dottedQuad = regexp.MustCompile(`\b\d{1,3}(?:[._]\d{1,3}){3}\b`)
	// epochRun is a long digit run: a timestamp or a per-send counter. Short
	// runs are left alone because a campaign id is short and structural.
	epochRun = regexp.MustCompile(`\d{10,}`)
)

const (
	zeroUUID  = "00000000-0000-0000-0000-000000000000"
	zeroEmail = "poc@example.com"
)

// Neutralize returns a copy of value with per-message fields replaced by inert
// values of the same shape, plus the paths it changed.
//
// Shape is preserved deliberately. A server that checks "32 hex characters"
// still sees 32 hex characters, so what is being tested is whether the value
// is *verified*, not whether it is well formed.
func Neutralize(value any) (any, []model.FieldPath) {
	out := clone(value)
	changed := []model.FieldPath{}

	for _, leaf := range leaves(out) {
		current, err := valueAt(out, leaf.steps)
		if err != nil {
			continue
		}

		text, ok := current.(string)
		if !ok {
			continue
		}

		next := neutralizeString(text)
		if next == text {
			continue
		}

		if err := setAt(out, leaf.steps, next); err == nil {
			changed = append(changed, leaf.Path)
		}
	}

	return out, changed
}

// neutralizeString rewrites the parts of one value that identify a single
// message, and leaves the rest alone.
func neutralizeString(s string) string {
	switch {
	case s == "":
		return s
	case uuidValue.MatchString(s):
		return zeroUUID
	case hexDigest.MatchString(s):
		return strings.Repeat("0", len(s))
	}

	// A composite value such as "<epoch>_<campaign>_..._<ip>-inbound0$<email>"
	// is rewritten piece by piece, so the campaign id survives and the parts
	// that vary per send do not.
	out := emailValue.ReplaceAllString(s, zeroEmail)
	out = dottedQuad.ReplaceAllStringFunc(out, zeroDigits)
	out = epochRun.ReplaceAllStringFunc(out, zeroDigits)

	return out
}

func zeroDigits(s string) string {
	var b strings.Builder

	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteByte('0')

			continue
		}

		b.WriteRune(r)
	}

	return b.String()
}

// Strategy names how a blob was mutated, so a finding can say which one
// worked. The distinction is the whole argument in a report: a preserved
// envelope proves the destination is unchecked, a neutralized one proves it is
// only bound to values an attacker can also supply.
type Strategy string

const (
	// StrategyPreserved changes the destination and nothing else.
	StrategyPreserved Strategy = "preserved-envelope"
	// StrategyNeutralized also replaces the per-message fields.
	StrategyNeutralized Strategy = "neutralized-envelope"
)

// ReplaceStrategy rebuilds base with dest in the given field, applying the
// named mutation strategy.
func (b Blob) ReplaceStrategy(base string, field URLField, dest string, strategy Strategy) (string, error) {
	value := clone(b.Chain.Value)

	if strategy == StrategyNeutralized {
		value, _ = Neutralize(value)
	}

	next := dest
	if field.Escaped {
		next = escapeLike(field.Value, dest)
	}

	if err := setAt(value, field.steps, next); err != nil {
		return "", err
	}

	return b.rebuild(base, value)
}

// escapeLike encodes dest the way the envelope encoded its own destination.
//
// Wrappers differ: some store "https%3A//host/path" with only the colon
// escaped, others escape everything. Matching what is already there keeps the
// mutation faithful to the format rather than to Go's defaults.
func escapeLike(original, dest string) string {
	if strings.Contains(original, "%2F") || strings.Contains(original, "%2f") {
		return fullEscape(dest)
	}

	// The common form leaves the slashes readable.
	return strings.ReplaceAll(fullEscape(dest), "%2F", "/")
}

func fullEscape(dest string) string {
	var b strings.Builder

	for _, r := range dest {
		switch r {
		case ':':
			b.WriteString("%3A")
		case '/':
			b.WriteString("%2F")
		case '?':
			b.WriteString("%3F")
		case '#':
			b.WriteString("%23")
		case '&':
			b.WriteString("%26")
		case '=':
			b.WriteString("%3D")
		default:
			b.WriteRune(r)
		}
	}

	return b.String()
}
