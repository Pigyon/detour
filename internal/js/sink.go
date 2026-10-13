package js

import (
	"strconv"
	"strings"

	tdjs "github.com/tdewolff/parse/v2/js"
)

// Sink kinds. Each names a way client-side code hands a string to the browser
// as a navigation destination.
const (
	SinkLocationHref     = "location.href"
	SinkLocationAssign   = "location.assign"
	SinkLocationReplace  = "location.replace"
	SinkWindowOpen       = "window.open"
	SinkRouterPush       = "router.push"
	SinkRouterReplace    = "router.replace"
	SinkDocumentLocation = "document.location"
	SinkTopLocation      = "top.location"
)

// Sink is one navigation sink and everything known about how it is reached.
type Sink struct {
	Kind string `json:"kind"`
	// Expression is the value handed to the sink, as written.
	Expression string `json:"expression"`
	// Function is the enclosing function, when it has a name.
	Function string `json:"function,omitempty"`
	// Guards are the conditions in effect at the sink, outermost first. An
	// empty list means the navigation is unguarded.
	Guards    []string   `json:"guards,omitempty"`
	Origin    Origin     `json:"origin"`
	Validator *Validator `json:"validator,omitempty"`
}

// Guarded reports whether any condition controls this sink.
func (s Sink) Guarded() bool {
	return len(s.Guards) > 0
}

// locationObjects are the receivers whose href, assign, and replace navigate.
var locationObjects = map[string]struct{}{
	"location":                 {},
	"window.location":          {},
	"document.location":        {},
	"top.location":             {},
	"self.location":            {},
	"parent.location":          {},
	"window.top.location":      {},
	"window.parent.location":   {},
	"globalThis.location":      {},
	"window.document.location": {},
}

// assignmentSinks maps a full assignment target to its sink kind.
var assignmentSinks = map[string]string{
	"location":                    SinkLocationHref,
	"location.href":               SinkLocationHref,
	"window.location":             SinkLocationHref,
	"window.location.href":        SinkLocationHref,
	"document.location":           SinkDocumentLocation,
	"document.location.href":      SinkDocumentLocation,
	"window.document.location":    SinkDocumentLocation,
	"top.location":                SinkTopLocation,
	"top.location.href":           SinkTopLocation,
	"window.top.location":         SinkTopLocation,
	"window.top.location.href":    SinkTopLocation,
	"parent.location":             SinkTopLocation,
	"parent.location.href":        SinkTopLocation,
	"window.parent.location":      SinkTopLocation,
	"window.parent.location.href": SinkTopLocation,
	"self.location":               SinkLocationHref,
	"self.location.href":          SinkLocationHref,
	"globalThis.location":         SinkLocationHref,
	"globalThis.location.href":    SinkLocationHref,
}

// scanner accumulates sinks while the visitor walks the tree.
type scanner struct {
	funcs    map[string]*function
	consts   map[string][]string
	bindings map[*tdjs.Var]tdjs.IExpr
	sinks    []Sink
}

// visitor carries the guard stack and enclosing function name down the tree.
// Each descent gets a fresh visitor, so a branch cannot leak its guards to a
// sibling.
type visitor struct {
	scan   *scanner
	guards []guard
	fn     string
}

// guard is one condition in effect at a sink. The expression is kept so the
// validator behind it can be resolved; the text is what a report shows.
type guard struct {
	text    string
	expr    tdjs.IExpr
	negated bool
}

func (v *visitor) with(expr tdjs.IExpr, negated bool) *visitor {
	text := render(expr)
	if negated {
		text = "!(" + text + ")"
	}

	next := &visitor{scan: v.scan, fn: v.fn}
	next.guards = make([]guard, len(v.guards)+1)
	copy(next.guards, v.guards)
	next.guards[len(v.guards)] = guard{text: text, expr: expr, negated: negated}

	return next
}

func (v *visitor) inFunc(name string) *visitor {
	return &visitor{scan: v.scan, guards: v.guards, fn: name}
}

// Exit satisfies tdjs.IVisitor. The guard stack lives on the visitor itself,
// so nothing has to be unwound here.
func (v *visitor) Exit(tdjs.INode) {}

// Enter records sinks and takes over descent for the nodes whose children are
// not all equal: an if statement guards its body but not its own condition.
func (v *visitor) Enter(n tdjs.INode) tdjs.IVisitor {
	switch node := n.(type) {
	case *tdjs.IfStmt:
		v.walkIf(node)

		return nil
	case *tdjs.CondExpr:
		v.walkCond(node)

		return nil
	case *tdjs.BinaryExpr:
		return v.walkBinary(node)
	case *tdjs.CallExpr:
		v.recordCall(node)

		return v
	case *tdjs.FuncDecl:
		return v.walkFunc(node)
	default:
		return v
	}
}

// walkIf descends the condition unguarded and the branches guarded by it.
func (v *visitor) walkIf(node *tdjs.IfStmt) {
	tdjs.Walk(v, node.Cond)
	tdjs.Walk(v.with(node.Cond, false), node.Body)

	if node.Else != nil {
		tdjs.Walk(v.with(node.Cond, true), node.Else)
	}
}

func (v *visitor) walkCond(node *tdjs.CondExpr) {
	tdjs.Walk(v, node.Cond)
	tdjs.Walk(v.with(node.Cond, false), node.X)
	tdjs.Walk(v.with(node.Cond, true), node.Y)
}

// walkBinary handles assignment sinks and short-circuit guards. A navigation
// behind && is guarded by whatever is on the left of it.
func (v *visitor) walkBinary(node *tdjs.BinaryExpr) tdjs.IVisitor {
	if node.Op == tdjs.EqToken {
		v.recordAssignment(node)

		return v
	}

	if node.Op == tdjs.AndToken {
		tdjs.Walk(v, node.X)
		tdjs.Walk(v.with(node.X, false), node.Y)

		return nil
	}

	return v
}

func (v *visitor) walkFunc(node *tdjs.FuncDecl) tdjs.IVisitor {
	if node.Name == nil {
		return v
	}

	return v.inFunc(string(node.Name.Name()))
}

func (v *visitor) recordAssignment(node *tdjs.BinaryExpr) {
	kind, ok := assignmentSinks[dotPath(node.X)]
	if !ok {
		return
	}

	v.add(kind, node.Y)
}

// recordCall matches location.assign/replace, window.open, and router
// navigation. The receiver is resolved through its full dotted path so
// window.location.assign and location.assign are the same sink.
func (v *visitor) recordCall(node *tdjs.CallExpr) {
	dot, ok := node.X.(*tdjs.DotExpr)
	if !ok {
		return
	}

	kind, ok := callSink(dotPath(dot.X), literalName(dot.Y))
	if !ok || len(node.Args.List) == 0 {
		return
	}

	v.add(kind, node.Args.List[0].Value)
}

func callSink(receiver, method string) (string, bool) {
	if _, ok := locationObjects[receiver]; ok {
		switch method {
		case "assign":
			return SinkLocationAssign, true
		case "replace":
			return SinkLocationReplace, true
		}
	}

	if method == "open" && (receiver == "window" || receiver == "self" || receiver == "globalThis") {
		return SinkWindowOpen, true
	}

	if isRouter(receiver) {
		switch method {
		case "push":
			return SinkRouterPush, true
		case "replace":
			return SinkRouterReplace, true
		}
	}

	return "", false
}

// isRouter matches the SPA router receivers by shape, so $router, this.router,
// and history all count without naming every framework.
func isRouter(receiver string) bool {
	tail := receiver
	if i := strings.LastIndex(receiver, "."); i >= 0 {
		tail = receiver[i+1:]
	}

	tail = strings.ToLower(strings.TrimPrefix(tail, "$"))

	return tail == "router" || tail == "history" || tail == "navigation"
}

func (v *visitor) add(kind string, value tdjs.IExpr) {
	guards := v.guards
	origin := v.scan.originOf(value)

	// A sink handed a bare identifier is guarded by whatever decided that
	// identifier's value, not by the statement it appears in.
	if def, resolved := v.scan.resolve(value); resolved {
		for _, expr := range guardsIn(def) {
			guards = append(guards, guard{text: render(expr), expr: expr})
		}

		// The defining expression names the real request parameter; the sink
		// itself only ever names the local that carries it.
		if defOrigin := v.scan.originOf(def); defOrigin.Param != "" || origin.Kind == OriginUnknown {
			origin = defOrigin
		}

		// A local assigned a fixed string is a constant destination.
		if _, isLit := stringLiteral(def); isLit {
			origin = Origin{Kind: OriginConstant}
		}
	}

	// A literal destination written straight into the sink is constant too.
	if _, isLit := stringLiteral(value); isLit {
		origin = Origin{Kind: OriginConstant}
	}

	texts := make([]string, 0, len(guards))
	for _, g := range guards {
		texts = append(texts, g.text)
	}

	sink := Sink{
		Kind:       kind,
		Expression: render(value),
		Function:   v.fn,
		Guards:     texts,
		Origin:     origin,
	}

	for i := len(guards) - 1; i >= 0 && sink.Validator == nil; i-- {
		sink.Validator = v.scan.validatorFor(guards[i])
	}

	v.scan.sinks = append(v.scan.sinks, sink)
}

// dotPath renders a member expression as a dotted path, so window.location.href
// becomes exactly that string. It returns an empty string for anything that is
// not a static path.
func dotPath(e tdjs.IExpr) string {
	switch node := e.(type) {
	case *tdjs.Var:
		return string(node.Name())
	case *tdjs.GroupExpr:
		return dotPath(node.X)
	case *tdjs.DotExpr:
		left := dotPath(node.X)
		if left == "" {
			return ""
		}

		return left + "." + literalName(node.Y)
	case *tdjs.IndexExpr:
		left := dotPath(node.X)

		key, ok := stringLiteral(node.Y)
		if left == "" || !ok {
			return ""
		}

		return left + "." + key
	case *tdjs.LiteralExpr:
		if node.TokenType == tdjs.ThisToken {
			return "this"
		}

		return ""
	case tdjs.LiteralExpr:
		if node.TokenType == tdjs.ThisToken {
			return "this"
		}

		return ""
	default:
		return ""
	}
}

// literalName reads a member name. The parser stores a DotExpr property as a
// LiteralExpr value while array elements hold pointers, so both forms matter.
func literalName(e tdjs.IExpr) string {
	switch node := e.(type) {
	case *tdjs.LiteralExpr:
		return string(node.Data)
	case tdjs.LiteralExpr:
		return string(node.Data)
	case *tdjs.Var:
		return string(node.Name())
	default:
		return ""
	}
}

// stringLiteral unquotes a string literal node, in either the pointer or the
// value form the parser produces.
func stringLiteral(e tdjs.IExpr) (string, bool) {
	var lit tdjs.LiteralExpr

	switch node := e.(type) {
	case *tdjs.LiteralExpr:
		lit = *node
	case tdjs.LiteralExpr:
		lit = node
	default:
		return "", false
	}

	if lit.TokenType != tdjs.StringToken {
		return "", false
	}

	raw := string(lit.Data)
	if unquoted, err := strconv.Unquote(raw); err == nil {
		return unquoted, true
	}

	// Single-quoted JS strings are not Go syntax, so trim the quotes directly.
	if len(raw) >= 2 {
		return raw[1 : len(raw)-1], true
	}

	return "", false
}

func render(n tdjs.INode) string {
	if n == nil {
		return ""
	}

	return n.String()
}
