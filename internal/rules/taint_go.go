package rules

import (
	sitter "github.com/smacker/go-tree-sitter"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/parse"
)

// This file implements a small, conservative **intra-procedural taint engine**
// for Go: values from untrusted *sources* are tracked through assignments and
// string concatenation to dangerous *sinks*. It is the seed of the broader
// dataflow work in Phase 5; it favours precision (few false positives) over
// completeness.
//
// Sources : os.Getenv(...), flag.Arg(...), os.Args[i]
// Sinks   : exec.Command/CommandContext (go:tainted-exec, CWE-78)
//           *.Query/Exec/QueryRow[Context] (go:tainted-sql, CWE-89)

func goTaintExecRule() Rule {
	return Rule{
		ID:        "go:tainted-exec",
		Name:      "Untrusted input flows into command execution",
		Type:      domain.TypeVulnerability,
		Severity:  domain.SevCritical,
		EffortMin: 30,
		Visit: taintVisitor(isExecSink,
			"Untrusted input reaches exec.Command without sanitization (command injection)."),
	}
}

func goTaintSQLRule() Rule {
	return Rule{
		ID:        "go:tainted-sql",
		Name:      "Untrusted input concatenated into a SQL query",
		Type:      domain.TypeVulnerability,
		Severity:  domain.SevCritical,
		EffortMin: 30,
		Visit: taintVisitor(isSQLSink,
			"Untrusted input reaches a SQL query; use parameterized queries instead of string concatenation."),
	}
}

// taintVisitor builds a Visit func: per top-level function, compute the tainted
// set, then flag sink calls (matched by isSink) that receive a tainted argument.
func taintVisitor(isSink func(*sitter.Node, []byte) bool, msg string) func(*sitter.Node, []byte, func(*sitter.Node, string)) {
	return func(root *sitter.Node, src []byte, emit func(*sitter.Node, string)) {
		parse.Walk(root, func(fn *sitter.Node) {
			t := fn.Type()
			if t != "function_declaration" && t != "method_declaration" {
				return
			}
			body := fn.ChildByFieldName("body")
			if body == nil {
				return
			}
			tainted := collectTainted(body, src)
			parse.Walk(body, func(n *sitter.Node) {
				if n.Type() != "call_expression" || !isSink(n, src) {
					return
				}
				args := n.ChildByFieldName("arguments")
				if args == nil {
					return
				}
				for i := 0; i < int(args.NamedChildCount()); i++ {
					if exprTainted(args.NamedChild(i), src, tainted) {
						emit(n, msg)
						return
					}
				}
			})
		})
	}
}

// collectTainted iteratively builds the set of tainted variable names in a
// function body (fixed-point over assignments).
func collectTainted(body *sitter.Node, src []byte) map[string]bool {
	tainted := map[string]bool{}
	for changed := true; changed; {
		changed = false
		parse.Walk(body, func(n *sitter.Node) {
			tt := n.Type()
			if tt != "short_var_declaration" && tt != "assignment_statement" {
				return
			}
			left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
			lname := identName(firstNamed(left), src)
			if lname == "" || tainted[lname] {
				return
			}
			if exprTainted(firstNamed(right), src, tainted) {
				tainted[lname] = true
				changed = true
			}
		})
	}
	return tainted
}

// exprTainted reports whether an expression carries taint (a source call, a
// tainted identifier, an os.Args index, or a concatenation involving any of
// these).
func exprTainted(n *sitter.Node, src []byte, tainted map[string]bool) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "identifier":
		return tainted[n.Content(src)]
	case "call_expression":
		return isSelectorCall(n, src, "os", "Getenv") || isSelectorCall(n, src, "flag", "Arg")
	case "index_expression":
		op := n.ChildByFieldName("operand")
		return op != nil && op.Type() == "selector_expression" &&
			selOperand(op, src) == "os" && selField(op, src) == "Args"
	case "binary_expression":
		return exprTainted(n.ChildByFieldName("left"), src, tainted) ||
			exprTainted(n.ChildByFieldName("right"), src, tainted)
	case "parenthesized_expression":
		return exprTainted(firstNamed(n), src, tainted)
	}
	return false
}

func firstNamed(n *sitter.Node) *sitter.Node {
	if n == nil || n.NamedChildCount() == 0 {
		return nil
	}
	return n.NamedChild(0)
}

func identName(n *sitter.Node, src []byte) string {
	if n != nil && n.Type() == "identifier" {
		return n.Content(src)
	}
	return ""
}

func selOperand(sel *sitter.Node, src []byte) string {
	if op := sel.ChildByFieldName("operand"); op != nil {
		return op.Content(src)
	}
	return ""
}

func selField(sel *sitter.Node, src []byte) string {
	if f := sel.ChildByFieldName("field"); f != nil {
		return f.Content(src)
	}
	return ""
}

// isSelectorCall reports whether call is `pkg.field(...)`.
func isSelectorCall(call *sitter.Node, src []byte, pkg, field string) bool {
	if call == nil || call.Type() != "call_expression" {
		return false
	}
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Type() != "selector_expression" {
		return false
	}
	return selOperand(fn, src) == pkg && selField(fn, src) == field
}

// isExecSink: exec.Command / exec.CommandContext.
func isExecSink(call *sitter.Node, src []byte) bool {
	return isSelectorCall(call, src, "exec", "Command") ||
		isSelectorCall(call, src, "exec", "CommandContext")
}

// isSQLSink: any *.Query/Exec/QueryRow[Context] call (database/sql, pgx, …).
func isSQLSink(call *sitter.Node, src []byte) bool {
	if call.Type() != "call_expression" {
		return false
	}
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Type() != "selector_expression" {
		return false
	}
	switch selField(fn, src) {
	case "Query", "QueryContext", "QueryRow", "QueryRowContext", "Exec", "ExecContext":
		return true
	}
	return false
}
