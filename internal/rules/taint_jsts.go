package rules

import (
	sitter "github.com/smacker/go-tree-sitter"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/parse"
)

// JS/TS intra-procedural taint: request data (req.* / request.*) flowing
// (through assignments and string concatenation) into eval() is injection.
//
// Source : member/subscript/call rooted at `req` or `request`
// Sink   : eval(...)   -> {js,ts}:tainted-eval (CWE-95)
func jsTaintEvalRule(prefix string) Rule {
	return Rule{
		ID:        prefix + ":tainted-eval",
		Name:      "Request data flows into eval()",
		Type:      domain.TypeVulnerability,
		Severity:  domain.SevCritical,
		EffortMin: 30,
		Visit:     visitJSTaintEval,
	}
}

func visitJSTaintEval(root *sitter.Node, src []byte, emit func(*sitter.Node, string)) {
	parse.Walk(root, func(fn *sitter.Node) {
		switch fn.Type() {
		case "function_declaration", "method_definition", "arrow_function", "function_expression", "function":
		default:
			return
		}
		body := fn.ChildByFieldName("body")
		if body == nil {
			return
		}
		tainted := collectTaintedJS(body, src)
		parse.Walk(body, func(n *sitter.Node) {
			if n.Type() != "call_expression" {
				return
			}
			callee := n.ChildByFieldName("function")
			if callee == nil || callee.Type() != "identifier" || callee.Content(src) != "eval" {
				return
			}
			args := n.ChildByFieldName("arguments")
			if args == nil {
				return
			}
			for i := 0; i < int(args.NamedChildCount()); i++ {
				if exprTaintedJS(args.NamedChild(i), src, tainted) {
					emit(n, "Request data reaches eval(); never eval untrusted input.")
					return
				}
			}
		})
	})
}

func collectTaintedJS(body *sitter.Node, src []byte) map[string]bool {
	tainted := map[string]bool{}
	for changed := true; changed; {
		changed = false
		parse.Walk(body, func(n *sitter.Node) {
			switch n.Type() {
			case "variable_declarator":
				name := identName(n.ChildByFieldName("name"), src)
				if name != "" && !tainted[name] && exprTaintedJS(n.ChildByFieldName("value"), src, tainted) {
					tainted[name] = true
					changed = true
				}
			case "assignment_expression":
				name := identName(n.ChildByFieldName("left"), src)
				if name != "" && !tainted[name] && exprTaintedJS(n.ChildByFieldName("right"), src, tainted) {
					tainted[name] = true
					changed = true
				}
			}
		})
	}
	return tainted
}

func exprTaintedJS(n *sitter.Node, src []byte, tainted map[string]bool) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "identifier":
		return tainted[n.Content(src)]
	case "member_expression", "subscript_expression":
		return jsReqAccess(n, src)
	case "call_expression":
		return jsReqAccess(n.ChildByFieldName("function"), src)
	case "binary_expression":
		return exprTaintedJS(n.ChildByFieldName("left"), src, tainted) ||
			exprTaintedJS(n.ChildByFieldName("right"), src, tainted)
	case "parenthesized_expression":
		return exprTaintedJS(firstNamed(n), src, tainted)
	case "template_string":
		for i := 0; i < int(n.NamedChildCount()); i++ {
			sub := n.NamedChild(i)
			if sub.Type() == "template_substitution" && exprTaintedJS(firstNamed(sub), src, tainted) {
				return true
			}
		}
	}
	return false
}

// jsReqAccess reports whether n is a member/subscript/call rooted at req/request.
func jsReqAccess(n *sitter.Node, src []byte) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "member_expression", "subscript_expression", "call_expression":
		root := jsRootObject(n, src)
		return root == "req" || root == "request"
	}
	return false
}

// jsRootObject follows the object/callee chain to the leftmost identifier.
func jsRootObject(n *sitter.Node, src []byte) string {
	for n != nil {
		switch n.Type() {
		case "member_expression", "subscript_expression":
			n = n.ChildByFieldName("object")
		case "call_expression":
			n = n.ChildByFieldName("function")
		case "identifier":
			return n.Content(src)
		default:
			return ""
		}
	}
	return ""
}
