package rules

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/parse"
)

// Python intra-procedural taint: untrusted input flowing (through assignments
// and string concatenation) into a DB cursor's execute() is SQL injection.
//
// Sources : input(), os.getenv(...), os.environ.get(...), request.*.get(...)
// Sink    : *.execute / *.executemany  (go:tainted-sql analogue, CWE-89)
func pythonTaintSQLRule() Rule {
	return Rule{
		ID:        "py:tainted-sql",
		Name:      "Untrusted input concatenated into a SQL query",
		Type:      domain.TypeVulnerability,
		Severity:  domain.SevCritical,
		EffortMin: 30,
		Visit: pyTaintVisitor(isPyExecuteSink,
			"Untrusted input reaches cursor.execute(); use parameterized queries (placeholders), not string concatenation."),
	}
}

func pythonTaintExecRule() Rule {
	return Rule{
		ID:        "py:tainted-exec",
		Name:      "Untrusted input flows into command execution",
		Type:      domain.TypeVulnerability,
		Severity:  domain.SevCritical,
		EffortMin: 30,
		Visit: pyTaintVisitor(isPyExecSink,
			"Untrusted input reaches os.system/subprocess; this is command injection. Pass an argument list and validate input."),
	}
}

// pyTaintVisitor builds a Visit func: per function, compute the tainted set,
// then flag sink calls (matched by isSink) that receive a tainted argument.
func pyTaintVisitor(isSink func(*sitter.Node, []byte) bool, msg string) func(*sitter.Node, []byte, func(*sitter.Node, string)) {
	return func(root *sitter.Node, src []byte, emit func(*sitter.Node, string)) {
		parse.Walk(root, func(fn *sitter.Node) {
			if fn.Type() != "function_definition" {
				return
			}
			body := fn.ChildByFieldName("body")
			if body == nil {
				return
			}
			tainted := collectTaintedPy(body, src)
			parse.Walk(body, func(n *sitter.Node) {
				if n.Type() != "call" || !isSink(n, src) {
					return
				}
				args := n.ChildByFieldName("arguments")
				if args == nil {
					return
				}
				for i := 0; i < int(args.NamedChildCount()); i++ {
					if exprTaintedPy(args.NamedChild(i), src, tainted) {
						emit(n, msg)
						return
					}
				}
			})
		})
	}
}

// isPyExecSink reports whether a call is os.system(...) or subprocess.<run-like>.
func isPyExecSink(call *sitter.Node, src []byte) bool {
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Type() != "attribute" {
		return false
	}
	obj, attr := "", ""
	if o := fn.ChildByFieldName("object"); o != nil {
		obj = o.Content(src)
	}
	if a := fn.ChildByFieldName("attribute"); a != nil {
		attr = a.Content(src)
	}
	if obj == "os" && (attr == "system" || attr == "popen") {
		return true
	}
	if obj == "subprocess" {
		switch attr {
		case "run", "call", "Popen", "check_output", "check_call":
			return true
		}
	}
	return false
}

func collectTaintedPy(body *sitter.Node, src []byte) map[string]bool {
	tainted := map[string]bool{}
	for changed := true; changed; {
		changed = false
		parse.Walk(body, func(n *sitter.Node) {
			t := n.Type()
			if t != "assignment" && t != "augmented_assignment" {
				return
			}
			lname := identName(n.ChildByFieldName("left"), src)
			if lname == "" || tainted[lname] {
				return
			}
			if exprTaintedPy(n.ChildByFieldName("right"), src, tainted) {
				tainted[lname] = true
				changed = true
			}
		})
	}
	return tainted
}

func exprTaintedPy(n *sitter.Node, src []byte, tainted map[string]bool) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "identifier":
		return tainted[n.Content(src)]
	case "call":
		if isPySource(n, src) {
			return true
		}
		// Taint propagates through "...".format(taint): the call is tainted if
		// the template or any argument is tainted.
		fn := n.ChildByFieldName("function")
		if fn != nil && fn.Type() == "attribute" {
			if a := fn.ChildByFieldName("attribute"); a != nil && a.Content(src) == "format" {
				if exprTaintedPy(fn.ChildByFieldName("object"), src, tainted) {
					return true
				}
				if args := n.ChildByFieldName("arguments"); args != nil {
					for i := 0; i < int(args.NamedChildCount()); i++ {
						if exprTaintedPy(args.NamedChild(i), src, tainted) {
							return true
						}
					}
				}
			}
		}
		return false
	case "string":
		// f-strings: tainted if any {interpolation} carries taint.
		for i := 0; i < int(n.NamedChildCount()); i++ {
			c := n.NamedChild(i)
			if c.Type() == "interpolation" && exprTaintedPy(firstNamed(c), src, tainted) {
				return true
			}
		}
		return false
	case "binary_operator":
		return exprTaintedPy(n.ChildByFieldName("left"), src, tainted) ||
			exprTaintedPy(n.ChildByFieldName("right"), src, tainted)
	case "parenthesized_expression":
		return exprTaintedPy(firstNamed(n), src, tainted)
	}
	return false
}

// isPySource reports whether a call expression is a known taint source.
func isPySource(call *sitter.Node, src []byte) bool {
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return false
	}
	if fn.Type() == "identifier" {
		return fn.Content(src) == "input"
	}
	if fn.Type() != "attribute" {
		return false
	}
	attr := ""
	if a := fn.ChildByFieldName("attribute"); a != nil {
		attr = a.Content(src)
	}
	obj := ""
	if o := fn.ChildByFieldName("object"); o != nil {
		obj = o.Content(src)
	}
	if attr == "getenv" && obj == "os" {
		return true
	}
	if attr == "get" {
		for _, m := range []string{"request", "environ", "args", "form", "values", "GET", "POST"} {
			if strings.Contains(obj, m) {
				return true
			}
		}
	}
	return false
}

// isPyExecuteSink reports whether a call is *.execute / *.executemany.
func isPyExecuteSink(call *sitter.Node, src []byte) bool {
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Type() != "attribute" {
		return false
	}
	a := fn.ChildByFieldName("attribute")
	if a == nil {
		return false
	}
	n := a.Content(src)
	return n == "execute" || n == "executemany"
}
