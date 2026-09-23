package js

import (
	"sort"
	"strings"

	tdjs "github.com/tdewolff/parse/v2/js"
)

// collectFunctions indexes every callable in the script by name. A guard is
// routinely attached to an object (the KuCoin bundle exports it as
// e.checkBackUrlIsSafe=function(e){...}), so assignments and properties count
// as declarations too, keyed on their last path segment.
func collectFunctions(ast *tdjs.AST) map[string]*function {
	out := map[string]*function{}
	tdjs.Walk(&funcCollector{out: out}, ast)

	return out
}

type funcCollector struct {
	out map[string]*function
}

func (c *funcCollector) Exit(tdjs.INode) {}

func (c *funcCollector) Enter(n tdjs.INode) tdjs.IVisitor {
	switch node := n.(type) {
	case *tdjs.FuncDecl:
		if node.Name != nil {
			c.put(string(node.Name.Name()), node.Params, &node.Body)
		}
	case *tdjs.MethodDecl:
		c.put(render(node.Name), node.Params, &node.Body)
	case *tdjs.VarDecl:
		c.readBindings(node)
	case *tdjs.BinaryExpr:
		c.readAssignment(node)
	case *tdjs.Property:
		c.readProperty(node)
	}

	return c
}

// readBindings picks up const f = () => {} and const f = function () {}.
func (c *funcCollector) readBindings(decl *tdjs.VarDecl) {
	for i := range decl.List {
		name, ok := bindingName(decl.List[i].Binding)
		if !ok {
			continue
		}

		c.putExpr(name, decl.List[i].Default)
	}
}

// readAssignment picks up obj.guard = function () {}, the shape a bundler
// emits for an exported guard.
func (c *funcCollector) readAssignment(node *tdjs.BinaryExpr) {
	if node.Op != tdjs.EqToken {
		return
	}

	path := dotPath(node.X)
	if path == "" {
		return
	}

	if i := strings.LastIndex(path, "."); i >= 0 {
		path = path[i+1:]
	}

	c.putExpr(path, node.Y)
}

func (c *funcCollector) readProperty(node *tdjs.Property) {
	if node.Name == nil {
		return
	}

	c.putExpr(render(node.Name), node.Value)
}

func (c *funcCollector) putExpr(name string, e tdjs.IExpr) {
	switch fn := e.(type) {
	case *tdjs.FuncDecl:
		c.put(name, fn.Params, &fn.Body)
	case *tdjs.ArrowFunc:
		c.put(name, fn.Params, &fn.Body)
	case *tdjs.GroupExpr:
		c.putExpr(name, fn.X)
	}
}

func (c *funcCollector) put(name string, params tdjs.Params, body *tdjs.BlockStmt) {
	name = strings.Trim(name, `"'`)
	if name == "" || body == nil {
		return
	}

	if _, dup := c.out[name]; dup {
		return
	}

	c.out[name] = &function{name: name, params: paramNames(params), body: body}
}

func paramNames(params tdjs.Params) []string {
	out := make([]string, 0, len(params.List))

	for i := range params.List {
		if name, ok := bindingName(params.List[i].Binding); ok {
			out = append(out, name)
		}
	}

	return out
}

func bindingName(b tdjs.IBinding) (string, bool) {
	v, ok := b.(*tdjs.Var)
	if !ok {
		return "", false
	}

	return string(v.Name()), true
}

// collectStringArrays indexes every named array of string literals, so a
// membership test over a module-level constant can be resolved to real hosts.
func collectStringArrays(ast *tdjs.AST) map[string][]string {
	out := map[string][]string{}
	tdjs.Walk(&arrayCollector{out: out}, ast)

	return out
}

type arrayCollector struct {
	out map[string][]string
}

func (c *arrayCollector) Exit(tdjs.INode) {}

func (c *arrayCollector) Enter(n tdjs.INode) tdjs.IVisitor {
	decl, ok := n.(*tdjs.VarDecl)
	if !ok {
		return c
	}

	for i := range decl.List {
		name, named := bindingName(decl.List[i].Binding)
		if !named {
			continue
		}

		if hosts, isArray := stringArray(decl.List[i].Default); isArray {
			c.out[name] = hosts
		}
	}

	return c
}

// stringArray reads an array literal of string literals.
func stringArray(e tdjs.IExpr) ([]string, bool) {
	arr, ok := e.(*tdjs.ArrayExpr)
	if !ok || len(arr.List) == 0 {
		return nil, false
	}

	out := make([]string, 0, len(arr.List))

	for _, item := range arr.List {
		s, isString := stringLiteral(item.Value)
		if !isString {
			return nil, false
		}

		out = append(out, s)
	}

	return out, true
}

// collectURLs pulls absolute URLs and rooted paths out of string literals.
// This is the endpoint inventory that would otherwise come from jsluice, and
// it feeds the harvest corpus.
func collectURLs(ast *tdjs.AST) []string {
	seen := map[string]struct{}{}
	tdjs.Walk(&urlCollector{seen: seen}, ast)

	out := make([]string, 0, len(seen))
	for u := range seen {
		out = append(out, u)
	}

	sort.Strings(out)

	return out
}

type urlCollector struct {
	seen map[string]struct{}
}

func (c *urlCollector) Exit(tdjs.INode) {}

func (c *urlCollector) Enter(n tdjs.INode) tdjs.IVisitor {
	lit, ok := n.(tdjs.IExpr)
	if !ok {
		return c
	}

	s, isString := stringLiteral(lit)
	if !isString || !looksLikeEndpoint(s) {
		return c
	}

	c.seen[s] = struct{}{}

	return c
}

func looksLikeEndpoint(s string) bool {
	if len(s) < 2 || len(s) > 2048 || strings.ContainsAny(s, " \t\n\"<>") {
		return false
	}

	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return true
	}

	return strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") && strings.Count(s, "/") >= 2
}

// collectBindings indexes what each variable was assigned, so a sink fed a
// bare identifier can be traced back to the expression that produced it. The
// KuCoin login handler is exactly this shape: the guard runs in a ternary
// that computes r, and only then is r handed to location.href.
//
// The table is keyed on the parser's resolved *Var rather than on a name.
// Minified bundles reuse single letters in every scope, and a name-keyed table
// silently resolves one scope's r to another's.
func collectBindings(ast *tdjs.AST) map[*tdjs.Var]tdjs.IExpr {
	out := map[*tdjs.Var]tdjs.IExpr{}
	tdjs.Walk(&bindingCollector{out: out}, ast)

	return out
}

type bindingCollector struct {
	out map[*tdjs.Var]tdjs.IExpr
}

func (c *bindingCollector) Exit(tdjs.INode) {}

func (c *bindingCollector) Enter(n tdjs.INode) tdjs.IVisitor {
	switch node := n.(type) {
	case *tdjs.VarDecl:
		for i := range node.List {
			if v, ok := node.List[i].Binding.(*tdjs.Var); ok && node.List[i].Default != nil {
				c.put(v, node.List[i].Default)
			}
		}
	case *tdjs.BinaryExpr:
		if node.Op == tdjs.EqToken {
			if v, ok := node.X.(*tdjs.Var); ok {
				c.put(v, node.Y)
			}
		}
	}

	return c
}

func (c *bindingCollector) put(v *tdjs.Var, e tdjs.IExpr) {
	key := canonical(v)
	if _, dup := c.out[key]; !dup {
		c.out[key] = e
	}
}

// canonical follows a use back to the variable it declares. The parser leaves
// a reference from an inner scope marked undeclared and links it to the outer
// declaration, so a use and its binding are often different nodes.
func canonical(v *tdjs.Var) *tdjs.Var {
	for range maxResolveDepth {
		if v.Link == nil {
			return v
		}

		v = v.Link
	}

	return v
}

// maxResolveDepth bounds identifier chasing so a self-referential binding
// cannot loop.
const maxResolveDepth = 6

// resolve follows a bare identifier back to the expression it was assigned.
//
// Exhausting the depth reports failure, not success. Reporting success while
// still holding a *tdjs.Var hands the caller an identifier that resolves to
// another identifier, and a caller that recurses on the result then never
// terminates. `var a = a` is enough to produce that, and a cycle across two
// bindings is an ordinary shape in minified code.
func (s *scanner) resolve(e tdjs.IExpr) (tdjs.IExpr, bool) {
	current := e

	for range maxResolveDepth {
		v, ok := current.(*tdjs.Var)
		if !ok {
			return current, current != e
		}

		next, found := s.bindings[canonical(v)]
		if !found {
			return current, current != e
		}

		current = next
	}

	return current, false
}

// guardsIn collects the conditions inside an expression that decide which
// value it produces: ternary tests and the left side of a short circuit.
func guardsIn(e tdjs.IExpr) []tdjs.IExpr {
	out := []tdjs.IExpr{}

	switch node := e.(type) {
	case *tdjs.GroupExpr:
		return guardsIn(node.X)
	case *tdjs.CondExpr:
		out = append(out, node.Cond)
		out = append(out, guardsIn(node.X)...)
		out = append(out, guardsIn(node.Y)...)
	case *tdjs.BinaryExpr:
		if node.Op == tdjs.AndToken || node.Op == tdjs.OrToken {
			out = append(out, node.X)
			out = append(out, guardsIn(node.Y)...)
		}
	}

	return out
}
