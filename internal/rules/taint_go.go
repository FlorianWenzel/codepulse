package rules

import (
	sitter "github.com/smacker/go-tree-sitter"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/parse"
)

// goTaintExecRule is a first, real **dataflow** check (not a syntactic match):
// within a function it tracks values that originate from a taint *source*
// (os.Getenv) through simple assignments, and flags when a tainted value
// reaches a command-execution *sink* (exec.Command / exec.CommandContext).
//
// This is deliberately intra-procedural and conservative (direct identifier
// flow + one-hop propagation); it demonstrates the dataflow approach the
// engine will generalize in Phase 5.
func goTaintExecRule() Rule {
	return Rule{
		ID:        "go:tainted-exec",
		Name:      "Untrusted input flows into command execution",
		Type:      domain.TypeVulnerability,
		Severity:  domain.SevCritical,
		EffortMin: 30,
		Visit:     visitGoTaintExec,
	}
}

func visitGoTaintExec(root *sitter.Node, src []byte, emit func(*sitter.Node, string)) {
	parse.Walk(root, func(fn *sitter.Node) {
		t := fn.Type()
		if t != "function_declaration" && t != "method_declaration" {
			return
		}
		body := fn.ChildByFieldName("body")
		if body == nil {
			return
		}

		// Pass 1: collect tainted variable names (sources + one-hop propagation).
		tainted := map[string]bool{}
		for changed := true; changed; {
			changed = false
			parse.Walk(body, func(n *sitter.Node) {
				tt := n.Type()
				if tt != "short_var_declaration" && tt != "assignment_statement" {
					return
				}
				left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
				if left == nil || right == nil {
					return
				}
				rhs := firstNamed(right)
				lname := identName(firstNamed(left), src)
				if lname == "" || tainted[lname] {
					return
				}
				if isSelectorCall(rhs, src, "os", "Getenv") ||
					(rhs != nil && rhs.Type() == "identifier" && tainted[rhs.Content(src)]) {
					tainted[lname] = true
					changed = true
				}
			})
		}

		// Pass 2: flag exec.Command(...) calls passed a tainted identifier.
		parse.Walk(body, func(n *sitter.Node) {
			if n.Type() != "call_expression" || !isExecCommandCall(n, src) {
				return
			}
			args := n.ChildByFieldName("arguments")
			if args == nil {
				return
			}
			for i := 0; i < int(args.NamedChildCount()); i++ {
				a := args.NamedChild(i)
				if a.Type() == "identifier" && tainted[a.Content(src)] {
					emit(n, "Untrusted input from os.Getenv reaches exec.Command without sanitization (command injection).")
					return
				}
			}
		})
	})
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

// isSelectorCall reports whether call is `pkg.field(...)`.
func isSelectorCall(call *sitter.Node, src []byte, pkg, field string) bool {
	if call == nil || call.Type() != "call_expression" {
		return false
	}
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Type() != "selector_expression" {
		return false
	}
	op := fn.ChildByFieldName("operand")
	f := fn.ChildByFieldName("field")
	return op != nil && f != nil && op.Content(src) == pkg && f.Content(src) == field
}

// isExecCommandCall reports whether call is exec.Command / exec.CommandContext.
func isExecCommandCall(call *sitter.Node, src []byte) bool {
	return isSelectorCall(call, src, "exec", "Command") ||
		isSelectorCall(call, src, "exec", "CommandContext")
}
