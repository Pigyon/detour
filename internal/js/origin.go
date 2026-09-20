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
	OriginQuery = "location.search"
	// OriginReferrer is document.referrer.
	OriginReferrer = "document.referrer"
	// OriginMessage is a postMessage payload.
	OriginMessage = "postMessage"
	// OriginStorage is localStorage or sessionStorage.
	OriginStorage = "storage"
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
	"callback": {}, "relaystate": {},
}

// originOf traces a sink expression back to the source that feeds it.
func originOf(e tdjs.IExpr) Origin {
	t := &originTracer{out: Origin{Kind: OriginUnknown}}
	tdjs.Walk(t, e)

	if t.out.Kind == OriginUnknown && t.param != "" {
		t.out.Kind = OriginQuery
	}

	t.out.Param = t.param

	return t.out
}

type originTracer struct {
	out   Origin
	param string
}

func (t *originTracer) Exit(tdjs.INode) {}

func (t *originTracer) Enter(n tdjs.INode) tdjs.IVisitor {
	switch node := n.(type) {
	case *tdjs.DotExpr:
		t.readPath(dotPath(node))
	case *tdjs.Var:
		t.readIdentifier(string(node.Name()))
	case *tdjs.CallExpr:
		t.readCall(node)
	}

	return t
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
	if !ok || len(call.Args.List) == 0 {
		return
	}

	method := literalName(dot.Y)
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
