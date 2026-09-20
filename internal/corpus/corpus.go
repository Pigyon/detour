package corpus

import (
	"sort"
)

// maxPerShape is how many URLs sharing one shape survive selection. Two is a
// deliberate compromise: one to attack, one spare in case the first is dead.
const maxPerShape = 2

// Corpus is the deduplicated, classified set of injection points a run will
// actually spend requests on.
type Corpus struct {
	entries []Entry
	shapes  map[string]int
	seen    map[string]struct{}
}

// New returns an empty corpus.
func New() *Corpus {
	return &Corpus{
		entries: []Entry{},
		shapes:  map[string]int{},
		seen:    map[string]struct{}{},
	}
}

// Add classifies a URL and keeps it if it is both interesting and not a
// repeat of a shape already covered. It reports whether the URL was kept.
func (c *Corpus) Add(raw string) bool {
	entry, ok := Classify(raw)
	if !ok {
		return false
	}

	if _, dup := c.seen[entry.URL]; dup {
		return false
	}

	shape, ok := Shape(entry.URL)
	if !ok {
		return false
	}

	// A vendor wrapper is a product, not an endpoint. Every instance is worth
	// keeping, because the campaign id and host differ per link and the
	// envelope is what is under test.
	if c.shapes[shape] >= maxPerShape && !entry.Has(KindVendorSig) {
		return false
	}

	c.seen[entry.URL] = struct{}{}
	c.shapes[shape]++
	c.entries = append(c.entries, entry)

	return true
}

// AddAll adds many URLs and returns how many were kept.
func (c *Corpus) AddAll(raws []string) int {
	kept := 0

	for _, raw := range raws {
		if c.Add(raw) {
			kept++
		}
	}

	return kept
}

// Entries returns the selected injection points, highest value first.
//
// The order is the priority a human would use: a vendor wrapper outranks a
// URL-shaped value, which outranks a redirect-shaped name, which outranks a
// merely opaque path.
func (c *Corpus) Entries() []Entry {
	out := make([]Entry, len(c.entries))
	copy(out, c.entries)

	sort.SliceStable(out, func(i, j int) bool {
		pi, pj := priority(out[i]), priority(out[j])
		if pi != pj {
			return pi > pj
		}

		return out[i].URL < out[j].URL
	})

	return out
}

// URLs returns just the selected URLs, in the same priority order, ready for
// the attack engine.
func (c *Corpus) URLs() []string {
	entries := c.Entries()

	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.URL)
	}

	return out
}

// Len is how many injection points were selected.
func (c *Corpus) Len() int {
	return len(c.entries)
}

func priority(e Entry) int {
	switch {
	case e.Has(KindVendorSig):
		return 4
	case e.Has(KindParamValue):
		return 3
	case e.Has(KindParamName):
		return 2
	case e.Has(KindPath):
		return 1
	default:
		return 0
	}
}
