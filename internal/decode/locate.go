package decode

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nedlir/detour/internal/model"
)

// step is one hop into a decoded structure. Carrying the steps alongside the
// printable path means a mutation never has to re-parse the path string.
type step struct {
	key   string
	index int
	isKey bool
}

// URLField is a navigation destination found inside a decoded envelope.
type URLField struct {
	Path model.FieldPath `json:"path"`
	// Value is the destination as a URL, after any percent-decoding.
	Value string `json:"value"`
	// Escaped records that the envelope stored the URL percent-encoded, so a
	// mutation has to re-encode it the same way.
	Escaped bool `json:"escaped"`

	steps []step
}

var plainKey = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// URLFields returns every destination in value, at any depth, including
// percent-encoded ones.
func URLFields(value any) []URLField {
	out := []URLField{}

	walk(value, "$", nil, func(path string, steps []step, leaf any) {
		s, ok := leaf.(string)
		if !ok {
			return
		}

		dest, escaped, ok := asURL(s)
		if !ok {
			return
		}

		out = append(out, URLField{
			Path:    model.FieldPath(path),
			Value:   dest,
			Escaped: escaped,
			steps:   steps,
		})
	})

	sortFields(out)

	return out
}

// sortFields gives map traversal a stable order so findings, reports, and the
// field matrix do not reshuffle between runs.
func sortFields(fields []URLField) {
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].Path < fields[j].Path
	})
}

func hasURLField(value any) bool {
	return len(URLFields(value)) > 0
}

// asURL reports whether s is a navigation destination, decoding it once if the
// envelope stored it percent-encoded.
func asURL(s string) (string, bool, bool) {
	if looksLikeURL(s) {
		return s, false, true
	}

	unescaped, err := url.QueryUnescape(s)
	if err != nil || unescaped == s {
		return "", false, false
	}

	if looksLikeURL(unescaped) {
		return unescaped, true, true
	}

	return "", false, false
}

// looksLikeURL accepts absolute http(s) URLs and protocol-relative ones. A
// bare path is not a destination worth attacking: it cannot leave the origin.
func looksLikeURL(s string) bool {
	if strings.HasPrefix(s, "//") && len(s) > 2 {
		return true
	}

	u, err := url.Parse(s)
	if err != nil {
		return false
	}

	if u.Host == "" {
		return false
	}

	return strings.EqualFold(u.Scheme, "http") || strings.EqualFold(u.Scheme, "https")
}

// walk visits every leaf in value, reporting its printable path and steps.
func walk(value any, path string, steps []step, visit func(string, []step, any)) {
	switch node := value.(type) {
	case map[string]any:
		for key, sub := range node {
			walk(sub, path+keyPath(key), appendStep(steps, step{key: key, isKey: true}), visit)
		}
	case []any:
		for i, sub := range node {
			walk(sub, path+"["+strconv.Itoa(i)+"]", appendStep(steps, step{index: i}), visit)
		}
	default:
		visit(path, steps, value)
	}
}

// appendStep always allocates, so sibling branches never share a backing
// array and overwrite each other's last step.
func appendStep(steps []step, s step) []step {
	out := make([]step, len(steps)+1)
	copy(out, steps)
	out[len(steps)] = s

	return out
}

func keyPath(key string) string {
	if plainKey.MatchString(key) {
		return "." + key
	}

	return "[" + strconv.Quote(key) + "]"
}

// setAt replaces the leaf at steps with v. It mutates value in place, so
// callers pass a clone.
func setAt(value any, steps []step, v any) error {
	if len(steps) == 0 {
		return errors.New("decode: cannot replace the root of an envelope")
	}

	parent := value

	for _, s := range steps[:len(steps)-1] {
		next, err := childAt(parent, s)
		if err != nil {
			return err
		}

		parent = next
	}

	return assign(parent, steps[len(steps)-1], v)
}

func childAt(parent any, s step) (any, error) {
	if s.isKey {
		obj, ok := parent.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("decode: %q is not an object key", s.key)
		}

		return obj[s.key], nil
	}

	arr, ok := parent.([]any)
	if !ok || s.index >= len(arr) {
		return nil, fmt.Errorf("decode: index %d is out of range", s.index)
	}

	return arr[s.index], nil
}

func assign(parent any, s step, v any) error {
	if s.isKey {
		obj, ok := parent.(map[string]any)
		if !ok {
			return fmt.Errorf("decode: %q is not an object key", s.key)
		}

		obj[s.key] = v

		return nil
	}

	arr, ok := parent.([]any)
	if !ok || s.index >= len(arr) {
		return fmt.Errorf("decode: index %d is out of range", s.index)
	}

	arr[s.index] = v

	return nil
}

// leaves returns every leaf in value, URL fields included, in a stable order.
func leaves(value any) []URLField {
	out := []URLField{}

	walk(value, "$", nil, func(path string, steps []step, leaf any) {
		out = append(out, URLField{
			Path:  model.FieldPath(path),
			Value: scalarString(leaf),
			steps: steps,
		})
	})

	sortFields(out)

	return out
}

// clone deep-copies a decoded structure so a mutation cannot leak into the
// next payload.
func clone(value any) any {
	switch node := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(node))
		for key, sub := range node {
			out[key] = clone(sub)
		}

		return out
	case []any:
		out := make([]any, len(node))
		for i, sub := range node {
			out[i] = clone(sub)
		}

		return out
	default:
		return value
	}
}

// flip returns a changed value of the same shape, used to probe whether the
// server validates a field.
func flip(v any) any {
	switch t := v.(type) {
	case string:
		return t + "x"
	case json.Number:
		if n, err := strconv.ParseInt(t.String(), 10, 64); err == nil {
			return json.Number(strconv.FormatInt(n+1, 10))
		}

		return json.Number("0")
	case bool:
		return !t
	case nil:
		return "detour"
	default:
		return v
	}
}
