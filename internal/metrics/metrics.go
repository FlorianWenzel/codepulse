// Package metrics computes size and complexity measures from a Go syntax tree.
package metrics

import (
	sitter "github.com/smacker/go-tree-sitter"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/parse"
)

// decisionNodes are the node types that add a branch to cyclomatic complexity.
var decisionNodes = map[string]bool{
	"if_statement":       true,
	"for_statement":      true,
	"expression_case":    true,
	"type_case":          true,
	"communication_case": true,
}

// funcNodes are the node types that introduce a function scope.
var funcNodes = map[string]bool{
	"function_declaration": true,
	"method_declaration":   true,
	"func_literal":         true,
}

// isLogicalOp reports whether a binary_expression node uses && or ||.
func isLogicalOp(n *sitter.Node, src []byte) bool {
	if n.Type() != "binary_expression" {
		return false
	}
	op := n.ChildByFieldName("operator")
	if op == nil {
		return false
	}
	t := op.Content(src)
	return t == "&&" || t == "||"
}

// cyclomaticOf returns the cyclomatic complexity of a subtree: 1 plus the
// number of decision points (branches and logical operators) inside it.
func cyclomaticOf(n *sitter.Node, src []byte) int {
	c := 1
	parse.Walk(n, func(node *sitter.Node) {
		if decisionNodes[node.Type()] || isLogicalOp(node, src) {
			c++
		}
	})
	return c
}

// CyclomaticOfFunc is cyclomaticOf exposed for the complexity rule.
func CyclomaticOfFunc(n *sitter.Node, src []byte) int { return cyclomaticOf(n, src) }

// FuncInfo describes one function found in a file.
type FuncInfo struct {
	Node       *sitter.Node
	Name       string
	Complexity int
}

// Functions returns every top-level function/method declaration with its
// name node and cyclomatic complexity. (func literals are excluded so we
// report on named functions only.)
func Functions(root *sitter.Node, src []byte) []FuncInfo {
	var out []FuncInfo
	parse.Walk(root, func(n *sitter.Node) {
		t := n.Type()
		if t != "function_declaration" && t != "method_declaration" {
			return
		}
		name := ""
		if id := n.ChildByFieldName("name"); id != nil {
			name = id.Content(src)
		}
		out = append(out, FuncInfo{Node: n, Name: name, Complexity: cyclomaticOf(n, src)})
	})
	return out
}

// cognitiveOf computes a simplified cognitive complexity: control-flow
// structures cost 1 plus the current nesting depth, and each && / || costs 1.
func cognitiveOf(root *sitter.Node, src []byte) int {
	var rec func(n *sitter.Node, nesting int) int
	rec = func(n *sitter.Node, nesting int) int {
		total := 0
		for i := 0; i < int(n.NamedChildCount()); i++ {
			c := n.NamedChild(i)
			switch c.Type() {
			case "if_statement", "for_statement",
				"expression_switch_statement", "type_switch_statement", "select_statement":
				total += 1 + nesting
				total += rec(c, nesting+1)
			case "binary_expression":
				if isLogicalOp(c, src) {
					total++
				}
				total += rec(c, nesting)
			default:
				total += rec(c, nesting)
			}
		}
		return total
	}
	return rec(root, 0)
}

// Compute returns all file-level metrics for a parsed Go file.
func Compute(path string, root *sitter.Node, src []byte) domain.FileMetrics {
	codeLines := map[int]bool{}
	commentLines := map[int]bool{}

	parse.Walk(root, func(n *sitter.Node) {
		if n.ChildCount() != 0 {
			return // only leaf tokens carry line attribution
		}
		start := int(n.StartPoint().Row)
		if n.Type() == "comment" {
			for r := start; r <= int(n.EndPoint().Row); r++ {
				commentLines[r] = true
			}
			return
		}
		codeLines[start] = true
	})

	// A line counts as a comment line only if it has no code on it.
	commentOnly := 0
	for r := range commentLines {
		if !codeLines[r] {
			commentOnly++
		}
	}

	funcs := Functions(root, src)
	fileComplexity, maxFunc := 0, 0
	for _, f := range funcs {
		fileComplexity += f.Complexity
		if f.Complexity > maxFunc {
			maxFunc = f.Complexity
		}
	}

	return domain.FileMetrics{
		Path:                path,
		Lines:               countLines(src),
		Ncloc:               len(codeLines),
		CommentLines:        commentOnly,
		Functions:           len(funcs),
		Complexity:          fileComplexity,
		CognitiveComplexity: cognitiveOf(root, src),
		MaxFuncComplexity:   maxFunc,
	}
}

// countLines returns the number of physical lines in src.
func countLines(src []byte) int {
	if len(src) == 0 {
		return 0
	}
	n := 1
	for _, b := range src {
		if b == '\n' {
			n++
		}
	}
	// don't count a trailing newline as an extra empty line
	if src[len(src)-1] == '\n' {
		n--
	}
	return n
}

// avoid unused import if funcNodes/decisionNodes set tweaked later
var _ = funcNodes
