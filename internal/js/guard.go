package js

import (
	"strings"

	"github.com/nedlir/detour/internal/model"
	tdjs "github.com/tdewolff/parse/v2/js"
)

// Match kinds, loosest first. The kind is how a guard compares a candidate
// host against what it trusts, and it is the single most useful fact about a
// validator: everything except equality has a bypass.
const (
	MatchSubstring = "substring"
	MatchSuffix    = "suffix"
	MatchPrefix    = "prefix"
	MatchRegex     = "regex"
	MatchEquality  = "equality"
	MatchUnknown   = "unknown"
)

// looseness orders match kinds so the weakest one found wins, since that is
// the one an attacker will use.
var looseness = map[string]int{
	MatchSubstring: 5,
	MatchSuffix:    4,
	MatchPrefix:    3,
	MatchRegex:     2,
	MatchEquality:  1,
	MatchUnknown:   0,
}

// Validator is what a guard function actually enforces, read off its body
// rather than its name.
type Validator struct {
	Name string `json:"name,omitempty"`
	Kind string `json:"kind"`
	// Allowlist is the set of trusted hosts when it is a literal in the script.
	Allowlist []string `json:"allowlist,omitempty"`
	// AllowlistRef names the expression the allowlist came from when its value
	// is not in this file, so a report can say what it could not resolve.
	AllowlistRef     string `json:"allowlist_ref,omitempty"`
	ChecksScheme     bool   `json:"checks_scheme"`
	AllowsHTTP       bool   `json:"allows_http"`
	ChecksUserinfo   bool   `json:"checks_userinfo"`
	BlocksJavaScript bool   `json:"blocks_javascript"`
	// DecodeCount is how many times the guard decodes its input. A validator
	// that decodes once where the sink decodes twice is the OR-B04 gap.
	DecodeCount int `json:"decode_count"`
	// Resolved is false when the guard was called but its body was not found,
	// so a reader can tell "no checks" from "not analyzable".
	Resolved bool `json:"resolved"`
}

// Model projects onto the engine's shared Validator type.
func (v Validator) Model() *model.Validator {
	return &model.Validator{
		Name:      v.Name,
		Source:    "js",
		Kind:      v.Kind,
		Allowlist: append([]string{}, v.Allowlist...),
	}
}

// function is a callable collected from the script.
type function struct {
	name   string
	params []string
	body   *tdjs.BlockStmt
}

// validatorFor resolves the guard in effect at a sink to the function it
// calls, then reads that function's body. A guard detour cannot resolve is
// reported unresolved rather than silently treated as absent.
func (s *scanner) validatorFor(g guard) *Validator {
	call := findCall(g.expr)
	if call == nil {
		return nil
	}

	name := calleeName(call)
	if name == "" {
		return nil
	}

	fn, ok := s.funcs[name]
	if !ok {
		return &Validator{Name: name, Kind: MatchUnknown}
	}

	v := s.analyze(fn)

	return &v
}

// findCall digs a call expression out of a guard condition, looking through
// negation, grouping, and boolean combination.
func findCall(e tdjs.IExpr) *tdjs.CallExpr {
	switch node := e.(type) {
	case *tdjs.CallExpr:
		return node
	case *tdjs.GroupExpr:
		return findCall(node.X)
	case *tdjs.UnaryExpr:
		return findCall(node.X)
	case *tdjs.BinaryExpr:
		if call := findCall(node.X); call != nil {
			return call
		}

		return findCall(node.Y)
	case *tdjs.CondExpr:
		return findCall(node.Cond)
	default:
		return nil
	}
}

func calleeName(call *tdjs.CallExpr) string {
	path := dotPath(call.X)
	if path == "" {
		return ""
	}

	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}

	return path
}

// analyze reads a guard function's body and records what it enforces.
func (s *scanner) analyze(fn *function) Validator {
	v := Validator{Name: fn.name, Kind: MatchUnknown, Resolved: true}
	tdjs.Walk(&guardVisitor{out: &v, scan: s}, fn.body)

	return v
}

// guardVisitor reads enforcement out of a function body structurally: which
// comparison is applied to a host, whether the scheme and userinfo are
// checked, and how many times the input is decoded.
type guardVisitor struct {
	out  *Validator
	scan *scanner
}

func (g *guardVisitor) Exit(tdjs.INode) {}

func (g *guardVisitor) Enter(n tdjs.INode) tdjs.IVisitor {
	switch node := n.(type) {
	case *tdjs.CallExpr:
		g.readCall(node)
	case *tdjs.DotExpr:
		g.readProperty(literalName(node.Y))
	case *tdjs.BinaryExpr:
		g.readComparison(node)
	case *tdjs.LiteralExpr:
		g.readLiteral(*node)
	case tdjs.LiteralExpr:
		g.readLiteral(node)
	}

	return g
}

// matchMethods maps a string method to the comparison it performs.
var matchMethods = map[string]string{
	"startsWith": MatchPrefix,
	"endsWith":   MatchSuffix,
	"includes":   MatchSubstring,
	"indexOf":    MatchSubstring,
	"search":     MatchSubstring,
	"match":      MatchRegex,
	"test":       MatchRegex,
}

// membershipMethods iterate an allowlist, so their receiver is the list.
var membershipMethods = map[string]struct{}{
	"some":     {},
	"find":     {},
	"filter":   {},
	"every":    {},
	"includes": {},
	"indexOf":  {},
}

func (g *guardVisitor) readCall(call *tdjs.CallExpr) {
	if isDecoder(calleeName(call)) {
		g.out.DecodeCount++
	}

	dot, ok := call.X.(*tdjs.DotExpr)
	if !ok {
		return
	}

	method := literalName(dot.Y)

	// An iteration method's receiver is a collection by definition. For
	// includes and indexOf it may equally be a URL string, so only a receiver
	// that really is a list counts as the allowlist.
	if _, isMembership := membershipMethods[method]; isMembership {
		if iterationMethods[method] || g.isList(dot.X) {
			g.readAllowlist(dot.X)
		}
	}

	g.readMatchArgument(method, call)

	// A regex test against a scheme blocklist is not the host comparison, so
	// it must not set the match kind. Missing this reads checkBackUrlIsSafe,
	// which compares hostnames for equality, as a loose regex match.
	if isSchemeBlocklist(dot.X) {
		return
	}

	g.note(g.matchKind(method, dot.X))
}

// iterationMethods walk a collection, so their receiver is always the list.
var iterationMethods = map[string]bool{
	"some": true, "find": true, "filter": true, "every": true,
}

// readMatchArgument records the literal a comparison tests against, which is
// the trusted value a bypass payload has to wear.
func (g *guardVisitor) readMatchArgument(method string, call *tdjs.CallExpr) {
	if _, isMatch := matchMethods[method]; !isMatch {
		return
	}

	if len(call.Args.List) == 0 || len(g.out.Allowlist) > 0 {
		return
	}

	value, ok := stringLiteral(call.Args.List[0].Value)
	if !ok || value == "" {
		return
	}

	g.out.Allowlist = []string{value}
}

func isDecoder(name string) bool {
	return name == "decodeURIComponent" || name == "decodeURI" || name == "unescape"
}

// matchKind decides what a method call actually compares. includes and indexOf
// mean equality over a list of hosts but a substring test over a URL string,
// and the two have opposite severities, so the receiver settles it.
func (g *guardVisitor) matchKind(method string, receiver tdjs.IExpr) string {
	kind, ok := matchMethods[method]
	if !ok {
		return MatchUnknown
	}

	if (method == "includes" || method == "indexOf") && g.isList(receiver) {
		return MatchEquality
	}

	return kind
}

// isList reports whether an expression is a list of hosts rather than a string.
func (g *guardVisitor) isList(e tdjs.IExpr) bool {
	if _, ok := stringArray(e); ok {
		return true
	}

	if name := dotPath(e); name != "" {
		if _, ok := g.scan.consts[name]; ok {
			return true
		}
	}

	if def, resolved := g.scan.resolve(e); resolved {
		_, ok := stringArray(def)

		return ok
	}

	return false
}

// readAllowlist resolves the thing a membership test runs over: a literal
// array in place, a named constant declared in this script, or an expression
// whose value lives elsewhere.
func (g *guardVisitor) readAllowlist(receiver tdjs.IExpr) {
	if len(g.out.Allowlist) > 0 || g.out.AllowlistRef != "" {
		return
	}

	if hosts, ok := stringArray(receiver); ok {
		g.out.Allowlist = hosts

		return
	}

	if name := dotPath(receiver); name != "" {
		if hosts, ok := g.scan.consts[name]; ok {
			g.out.Allowlist = append([]string{}, hosts...)

			return
		}
	}

	if def, resolved := g.scan.resolve(receiver); resolved {
		if hosts, ok := stringArray(def); ok {
			g.out.Allowlist = hosts

			return
		}

		receiver = def
	}

	if ref := g.refFor(receiver); ref != "" {
		g.out.AllowlistRef = ref
	}
}

// isSchemeBlocklist reports whether an expression is a regular expression
// matching a dangerous scheme rather than a host.
func isSchemeBlocklist(e tdjs.IExpr) bool {
	var lit tdjs.LiteralExpr

	switch node := e.(type) {
	case *tdjs.LiteralExpr:
		lit = *node
	case tdjs.LiteralExpr:
		lit = node
	default:
		return false
	}

	if lit.TokenType != tdjs.RegExpToken {
		return false
	}

	text := strings.ToLower(string(lit.Data))

	return strings.Contains(text, "javascript") ||
		strings.Contains(text, "vbscript") ||
		strings.Contains(text, "data:")
}

// refFor names an allowlist detour could not evaluate, preferring the property
// the list was ultimately read from. It follows identifiers through their
// bindings, so an intermediate variable does not become the reported name.
func (g *guardVisitor) refFor(e tdjs.IExpr) string {
	switch node := e.(type) {
	case *tdjs.GroupExpr:
		return g.refFor(node.X)
	case *tdjs.BinaryExpr:
		if ref := g.refFor(node.X); ref != "" {
			return ref
		}

		return g.refFor(node.Y)
	case *tdjs.CondExpr:
		if ref := g.refFor(node.X); ref != "" {
			return ref
		}

		return g.refFor(node.Y)
	case *tdjs.ArrayExpr:
		for _, item := range node.List {
			if ref := g.refFor(item.Value); ref != "" {
				return ref
			}
		}

		return ""
	case *tdjs.DotExpr:
		return literalName(node.Y)
	case *tdjs.Var:
		if def, resolved := g.scan.resolve(node); resolved {
			return g.refFor(def)
		}

		return string(node.Name())
	default:
		return render(e)
	}
}

func (g *guardVisitor) readProperty(name string) {
	switch name {
	case "protocol", "scheme":
		g.out.ChecksScheme = true
	case "username", "password":
		g.out.ChecksUserinfo = true
	}
}

// readComparison treats an equality test against a host as the strictest
// possible match, and records a scheme comparison that still admits http.
func (g *guardVisitor) readComparison(node *tdjs.BinaryExpr) {
	if node.Op != tdjs.EqEqToken && node.Op != tdjs.EqEqEqToken &&
		node.Op != tdjs.NotEqToken && node.Op != tdjs.NotEqEqToken {
		return
	}

	if comparesHost(node.X) || comparesHost(node.Y) {
		g.note(MatchEquality)
	}

	for _, side := range []tdjs.IExpr{node.X, node.Y} {
		if s, ok := stringLiteral(side); ok && strings.EqualFold(s, "http:") {
			g.out.AllowsHTTP = true
		}
	}
}

func comparesHost(e tdjs.IExpr) bool {
	name := literalNameOfProperty(e)

	return name == "hostname" || name == "host" || name == "domain"
}

func literalNameOfProperty(e tdjs.IExpr) string {
	dot, ok := e.(*tdjs.DotExpr)
	if !ok {
		return ""
	}

	return literalName(dot.Y)
}

// readLiteral catches the javascript-scheme blocklist, which is written as a
// regular expression far more often than as a string comparison.
func (g *guardVisitor) readLiteral(lit tdjs.LiteralExpr) {
	text := string(lit.Data)

	if lit.TokenType == tdjs.RegExpToken {
		if strings.Contains(strings.ToLower(text), "javascript") {
			g.out.BlocksJavaScript = true
		}

		return
	}

	if lit.TokenType != tdjs.StringToken {
		return
	}

	lower := strings.ToLower(text)

	if strings.Contains(lower, "javascript") {
		g.out.BlocksJavaScript = true
	}

	if strings.Contains(lower, "http://") {
		g.out.AllowsHTTP = true
	}

	if strings.Contains(lower, "https:") || strings.Contains(lower, "http:") {
		g.out.ChecksScheme = true
	}
}

// note keeps the loosest match kind seen, because that is the one that gets
// exploited.
func (g *guardVisitor) note(kind string) {
	if looseness[kind] > looseness[g.out.Kind] {
		g.out.Kind = kind
	}
}
