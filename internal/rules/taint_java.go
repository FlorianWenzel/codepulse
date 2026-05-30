package rules

import (
	sitter "github.com/smacker/go-tree-sitter"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/parse"
)

// Java intra-procedural taint: untrusted HTTP request data flowing (through
// local assignments, string concatenation, and String.format/.concat) into a
// JDBC execute call is SQL injection.
//
// Sources : request.getParameter/getParameterValues/getHeader/getQueryString/getCookies
// Sink    : Statement.executeQuery/executeUpdate/execute, Connection.prepareStatement,
//
//	addBatch  -> java:tainted-sql (CWE-89)
func javaTaintSQLRule() Rule {
	return Rule{
		ID:        "java:tainted-sql",
		Name:      "Untrusted request data concatenated into a SQL query",
		Type:      domain.TypeVulnerability,
		Severity:  domain.SevCritical,
		EffortMin: 30,
		Visit: javaTaintVisitor(isJavaSQLSink,
			"Untrusted request data reaches a SQL execute call; use a PreparedStatement with bind parameters (?), not string concatenation."),
	}
}

func javaTaintExecRule() Rule {
	return Rule{
		ID:        "java:tainted-exec",
		Name:      "Untrusted request data flows into command execution",
		Type:      domain.TypeVulnerability,
		Severity:  domain.SevCritical,
		EffortMin: 30,
		Visit: javaTaintVisitor(isJavaExecSink,
			"Untrusted request data reaches Runtime.exec; this is command injection. Use ProcessBuilder with a validated argument list."),
	}
}

// javaTaintVisitor builds a Visit func: per method/constructor, compute the
// tainted set, then flag sink calls (matched by isSink) with a tainted argument.
func javaTaintVisitor(isSink func(*sitter.Node, []byte) bool, msg string) func(*sitter.Node, []byte, func(*sitter.Node, string)) {
	return func(root *sitter.Node, src []byte, emit func(*sitter.Node, string)) {
		parse.Walk(root, func(fn *sitter.Node) {
			t := fn.Type()
			if t != "method_declaration" && t != "constructor_declaration" {
				return
			}
			body := fn.ChildByFieldName("body")
			if body == nil {
				return
			}
			tainted := collectTaintedJava(body, src)
			parse.Walk(body, func(n *sitter.Node) {
				if n.Type() != "method_invocation" || !isSink(n, src) {
					return
				}
				args := n.ChildByFieldName("arguments")
				if args == nil {
					return
				}
				for i := 0; i < int(args.NamedChildCount()); i++ {
					if exprTaintedJava(args.NamedChild(i), src, tainted) {
						emit(n, msg)
						return
					}
				}
			})
		})
	}
}

// collectTaintedJava builds the set of tainted local variable names in a method
// body (fixed-point over declarations and assignments).
func collectTaintedJava(body *sitter.Node, src []byte) map[string]bool {
	tainted := map[string]bool{}
	for changed := true; changed; {
		changed = false
		parse.Walk(body, func(n *sitter.Node) {
			switch n.Type() {
			case "variable_declarator":
				name := identName(n.ChildByFieldName("name"), src)
				if name != "" && !tainted[name] && exprTaintedJava(n.ChildByFieldName("value"), src, tainted) {
					tainted[name] = true
					changed = true
				}
			case "assignment_expression":
				name := identName(n.ChildByFieldName("left"), src)
				if name != "" && !tainted[name] && exprTaintedJava(n.ChildByFieldName("right"), src, tainted) {
					tainted[name] = true
					changed = true
				}
			}
		})
	}
	return tainted
}

func exprTaintedJava(n *sitter.Node, src []byte, tainted map[string]bool) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "identifier":
		return tainted[n.Content(src)]
	case "method_invocation":
		if isJavaSource(n, src) {
			return true
		}
		// Taint propagates through String.format(...) and s.concat(...).
		if name := javaMethodName(n, src); name == "format" || name == "concat" {
			if exprTaintedJava(n.ChildByFieldName("object"), src, tainted) {
				return true
			}
			if args := n.ChildByFieldName("arguments"); args != nil {
				for i := 0; i < int(args.NamedChildCount()); i++ {
					if exprTaintedJava(args.NamedChild(i), src, tainted) {
						return true
					}
				}
			}
		}
		return false
	case "binary_expression":
		return exprTaintedJava(n.ChildByFieldName("left"), src, tainted) ||
			exprTaintedJava(n.ChildByFieldName("right"), src, tainted)
	case "parenthesized_expression":
		return exprTaintedJava(firstNamed(n), src, tainted)
	}
	return false
}

func javaMethodName(mi *sitter.Node, src []byte) string {
	if n := mi.ChildByFieldName("name"); n != nil {
		return n.Content(src)
	}
	return ""
}

// isJavaSource reports whether a method_invocation reads untrusted request data.
func isJavaSource(mi *sitter.Node, src []byte) bool {
	switch javaMethodName(mi, src) {
	case "getParameter", "getParameterValues", "getHeader", "getQueryString", "getCookies":
		return true
	}
	return false
}

// isJavaSQLSink reports whether a method_invocation runs a SQL string.
func isJavaSQLSink(mi *sitter.Node, src []byte) bool {
	switch javaMethodName(mi, src) {
	case "executeQuery", "executeUpdate", "execute", "prepareStatement", "addBatch":
		return true
	}
	return false
}

// isJavaExecSink reports whether a method_invocation runs an OS command
// (Runtime.exec(...)).
func isJavaExecSink(mi *sitter.Node, src []byte) bool {
	return javaMethodName(mi, src) == "exec"
}
