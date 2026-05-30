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

// jsForEachFn calls do(body, taintedSet) for each function body.
func jsForEachFn(root *sitter.Node, src []byte, do func(body *sitter.Node, tainted map[string]bool)) {
	parse.Walk(root, func(fn *sitter.Node) {
		switch fn.Type() {
		case "function_declaration", "method_definition", "arrow_function", "function_expression", "function":
		default:
			return
		}
		if body := fn.ChildByFieldName("body"); body != nil {
			do(body, collectTaintedJS(body, src))
		}
	})
}

// anyArgTainted reports whether any argument of a call is tainted.
func anyArgTainted(call *sitter.Node, src []byte, tainted map[string]bool) bool {
	args := call.ChildByFieldName("arguments")
	if args == nil {
		return false
	}
	for i := 0; i < int(args.NamedChildCount()); i++ {
		if exprTaintedJS(args.NamedChild(i), src, tainted) {
			return true
		}
	}
	return false
}

// jsMemberProp returns the property name of a member_expression (or "").
func jsMemberProp(n *sitter.Node, src []byte) string {
	if n == nil || n.Type() != "member_expression" {
		return ""
	}
	if p := n.ChildByFieldName("property"); p != nil {
		return p.Content(src)
	}
	return ""
}

func visitJSTaintEval(root *sitter.Node, src []byte, emit func(*sitter.Node, string)) {
	jsForEachFn(root, src, func(body *sitter.Node, tainted map[string]bool) {
		parse.Walk(body, func(n *sitter.Node) {
			if n.Type() != "call_expression" {
				return
			}
			callee := n.ChildByFieldName("function")
			if callee == nil || callee.Type() != "identifier" || callee.Content(src) != "eval" {
				return
			}
			if anyArgTainted(n, src, tainted) {
				emit(n, "Request data reaches eval(); never eval untrusted input.")
			}
		})
	})
}

func jsTaintXSSRule(prefix string) Rule {
	return Rule{
		ID: prefix + ":tainted-xss", Name: "Request data assigned to innerHTML",
		Type: domain.TypeVulnerability, Severity: domain.SevCritical, EffortMin: 30,
		Visit: func(root *sitter.Node, src []byte, emit func(*sitter.Node, string)) {
			jsForEachFn(root, src, func(body *sitter.Node, tainted map[string]bool) {
				parse.Walk(body, func(n *sitter.Node) {
					if n.Type() != "assignment_expression" {
						return
					}
					p := jsMemberProp(n.ChildByFieldName("left"), src)
					if (p == "innerHTML" || p == "outerHTML") && exprTaintedJS(n.ChildByFieldName("right"), src, tainted) {
						emit(n, "Request data assigned to innerHTML enables XSS; use textContent or sanitize.")
					}
				})
			})
		},
	}
}

func jsTaintSSRFRule(prefix string) Rule {
	return Rule{
		ID: prefix + ":tainted-ssrf", Name: "Request data flows into an outbound HTTP request",
		Type: domain.TypeHotspot, Severity: domain.SevMajor, EffortMin: 30,
		Visit: func(root *sitter.Node, src []byte, emit func(*sitter.Node, string)) {
			jsForEachFn(root, src, func(body *sitter.Node, tainted map[string]bool) {
				parse.Walk(body, func(n *sitter.Node) {
					if n.Type() != "call_expression" {
						return
					}
					if isJSHTTPEgress(n.ChildByFieldName("function"), src) && anyArgTainted(n, src, tainted) {
						emit(n, "Request data controls an outbound HTTP request URL (SSRF); validate against an allow-list of hosts.")
					}
				})
			})
		},
	}
}

// isJSHTTPEgress reports whether a call target performs an outbound HTTP request
// (fetch / axios / got / http(s).get|request).
func isJSHTTPEgress(callee *sitter.Node, src []byte) bool {
	if callee == nil {
		return false
	}
	switch callee.Type() {
	case "identifier":
		switch callee.Content(src) {
		case "fetch", "axios", "got", "request", "superagent":
			return true
		}
	case "member_expression":
		switch jsRootObject(callee, src) {
		case "axios", "http", "https", "got", "superagent":
			return true
		}
	}
	return false
}

func jsTaintSQLRule(prefix string) Rule {
	return Rule{
		ID: prefix + ":tainted-sql", Name: "Request data flows into a SQL query",
		Type: domain.TypeVulnerability, Severity: domain.SevCritical, EffortMin: 30,
		Visit: func(root *sitter.Node, src []byte, emit func(*sitter.Node, string)) {
			jsForEachFn(root, src, func(body *sitter.Node, tainted map[string]bool) {
				parse.Walk(body, func(n *sitter.Node) {
					if n.Type() != "call_expression" {
						return
					}
					p := jsMemberProp(n.ChildByFieldName("function"), src)
					if (p == "query" || p == "execute") && anyArgTainted(n, src, tainted) {
						emit(n, "Request data reaches a SQL query; use parameterized queries / placeholders, not string concatenation or template literals.")
					}
				})
			})
		},
	}
}

func jsTaintExecRule(prefix string) Rule {
	return Rule{
		ID: prefix + ":tainted-exec", Name: "Request data flows into command execution",
		Type: domain.TypeVulnerability, Severity: domain.SevCritical, EffortMin: 30,
		Visit: func(root *sitter.Node, src []byte, emit func(*sitter.Node, string)) {
			jsForEachFn(root, src, func(body *sitter.Node, tainted map[string]bool) {
				parse.Walk(body, func(n *sitter.Node) {
					if n.Type() != "call_expression" {
						return
					}
					p := jsMemberProp(n.ChildByFieldName("function"), src)
					if (p == "exec" || p == "execSync") && anyArgTainted(n, src, tainted) {
						emit(n, "Request data reaches a command-execution call; validate input or avoid shell exec.")
					}
				})
			})
		},
	}
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
