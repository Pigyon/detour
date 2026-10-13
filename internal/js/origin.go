package js

import (
	"strings"

	tdjs "github.com/tdewolff/parse/v2/js"
)

// Origin kinds name where a sink's value comes from. The kind decides which
// technique a finding belongs to and whether a server-side test could ever
// have seen it.
const (
	// OriginHash is location.hash, which never reaches the server at all.
	OriginHash = "location.hash"
	// OriginQuery is the query string, readable server-side.
	OriginQuery    = "location.search"
	OriginReferrer = "document.referrer"
	// OriginStorage is localStorage or sessionStorage.
	OriginStorage = "storage"
	// OriginSelf is the whole current location (location.href,
	// location.toString(), document.URL). Navigating there stays on the current
	// origin, so it is not an attacker-controllable redirect destination even
	// when a carrier variable happens to be named like a redirect parameter.
	OriginSelf = "location.self"
	// OriginConstant is a string literal destination, fixed in the code and so
	// not attacker-controllable.
	OriginConstant = "constant"
	// OriginUnknown means the value was not traced to a controllable source.
	OriginUnknown = "unknown"
)

// Origin is where a sink's value came from.
type Origin struct {
	Kind string `json:"kind"`
	// Param is the query or route parameter name, when one was named.
	Param string `json:"param,omitempty"`
}

// redirectParams are the parameter names that carry a destination. They are
// used only to name a parameter already reaching a sink, never to decide on
// their own that something is a finding.
var redirectParams = map[string]struct{}{
	"url": {}, "next": {}, "redirect": {}, "redirect_uri": {}, "return": {},
	"returnurl": {}, "return_to": {}, "back": {}, "backurl": {}, "dest": {},
	"destination": {}, "goto": {}, "continue": {}, "rurl": {}, "redir": {},
	"uri": {}, "target": {}, "to": {}, "out": {}, "forward": {}, "link": {},
	"callback": {}, "relaystate": {}, "wreply": {},
}

// originOf traces a sink expression back to the source that feeds it,
// following bare identifiers into the expression they were assigned so a local
// is classified by its real source rather than by its name.
func (s *scanner) originOf(e tdjs.IExpr) Origin {
	t := &originTracer{out: Origin{Kind: OriginUnknown}, scan: s, seen: map[*tdjs.Var]struct{}{}}
	tdjs.Walk(t, e)

	switch {
	case t.out.Kind != OriginUnknown:
		// A concrete controllable source (search, hash, storage) was found and
		// outranks the name heuristic.
	case t.selfLocation:
		// The value is the whole current location: self-navigation, not a
		// redirect source. This wins over the redirect-param name heuristic,
		// which is exactly what used to misread `uri = location.toString()`.
		t.out.Kind = OriginSelf
	case t.param != "":
		t.out.Kind = OriginQuery
	}

	t.out.Param = t.param

	return t.out
}

type originTracer struct {
	out          Origin
	param        string
	selfLocation bool
	scan         *scanner
	seen         map[*tdjs.Var]struct{}
}

func (t *originTracer) Exit(tdjs.INode) {}

func (t *originTracer) Enter(n tdjs.INode) tdjs.IVisitor {
	switch node := n.(type) {
	case *tdjs.DotExpr:
		t.readPath(dotPath(node))
	case *tdjs.Var:
		t.readIdentifier(string(node.Name()))
		t.followBinding(node)
	case *tdjs.CallExpr:
		t.readCall(node)
	}

	return t
}

// followBinding traces a bare identifier into the expression it was assigned,
// so a local carrying location.search (or the whole location) is classified by
// that source and not by the local's name. A seen set guards against a cycle.
func (t *originTracer) followBinding(v *tdjs.Var) {
	if t.scan == nil {
		return
	}

	key := canonical(v)
	if _, done := t.seen[key]; done {
		return
	}

	t.seen[key] = struct{}{}

	if def, ok := t.scan.bindings[key]; ok {
		tdjs.Walk(t, def)
	}
}

// pathOrigins maps a well-known browser property to the origin it represents.
var pathOrigins = map[string]string{
	"hash":           OriginHash,
	"search":         OriginQuery,
	"referrer":       OriginReferrer,
	"localStorage":   OriginStorage,
	"sessionStorage": OriginStorage,
}

func (t *originTracer) readPath(path string) {
	if path == "" {
		return
	}

	if isWholeLocation(path) {
		t.selfLocation = true
	}

	tail := path
	if i := strings.LastIndex(path, "."); i >= 0 {
		tail = path[i+1:]
	}

	if kind, ok := pathOrigins[tail]; ok {
		t.set(kind)
	}

	if strings.Contains(path, "searchParams") || strings.Contains(path, "query") {
		t.set(OriginQuery)
	}
}

// wholeLocationPaths are reads of the entire current URL (not just a
// controllable piece like .search or .hash).
var wholeLocationPaths = map[string]struct{}{
	"document.url":         {},
	"document.documenturi": {},
	"document.baseuri":     {},
}

// isWholeLocation reports whether a dotted path reads the whole current
// location: a location object itself, its .href, or document.URL and friends.
func isWholeLocation(path string) bool {
	if _, ok := wholeLocationPaths[strings.ToLower(path)]; ok {
		return true
	}

	if _, ok := locationObjects[path]; ok {
		return true
	}

	if trimmed, ok := strings.CutSuffix(path, ".href"); ok {
		if _, isLoc := locationObjects[trimmed]; isLoc {
			return true
		}
	}

	return false
}

func (t *originTracer) readIdentifier(name string) {
	if _, ok := redirectParams[strings.ToLower(name)]; ok && t.param == "" {
		t.param = name
	}

	if name == "localStorage" || name == "sessionStorage" {
		t.set(OriginStorage)
	}
}

// readCall picks the parameter name out of a getter, so
// searchParams.get("backUrl") names backUrl.
func (t *originTracer) readCall(call *tdjs.CallExpr) {
	dot, ok := call.X.(*tdjs.DotExpr)
	if !ok {
		return
	}

	method := literalName(dot.Y)

	// location.toString() / window.location.toString() yields the whole current
	// URL, the same as reading location.href: self-referential, not a redirect
	// source.
	if method == "toString" {
		if _, isLoc := locationObjects[dotPath(dot.X)]; isLoc {
			t.selfLocation = true
		}

		return
	}

	if len(call.Args.List) == 0 {
		return
	}

	if method != "get" && method != "getItem" && method != "param" {
		return
	}

	name, isString := stringLiteral(call.Args.List[0].Value)
	if !isString {
		return
	}

	if t.param == "" {
		t.param = name
	}

	if method == "getItem" {
		t.set(OriginStorage)
	}
}

// set keeps the first concrete origin found. location.hash outranks
// everything, because a fragment is invisible to every server-side test and
// that fact changes which stage can confirm the finding.
func (t *originTracer) set(kind string) {
	if t.out.Kind == OriginHash {
		return
	}

	if t.out.Kind == OriginUnknown || kind == OriginHash {
		t.out.Kind = kind
	}
}
