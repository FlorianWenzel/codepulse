// Package metrics computes size and complexity measures from a syntax tree,
// driven by a per-language Spec so the same code works across languages.
package metrics

import (
	sitter "github.com/smacker/go-tree-sitter"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/langspec"
	"github.com/FlorianWenzel/codepulse/internal/parse"
)

// cyclomaticOf returns the cyclomatic complexity of a subtree: 1 plus the
// number of decision points (branches and logical operators) inside it.
func cyclomaticOf(spec langspec.Spec, n *sitter.Node, src []byte) int {
	c := 1
	parse.Walk(n, func(node *sitter.Node) {
		if spec.Decision[node.Type()] || spec.IsLogical(node, src) {
			c++
		}
	})
	return c
}

// CyclomaticOfFunc is cyclomaticOf exposed for the complexity rule.
func CyclomaticOfFunc(spec langspec.Spec, n *sitter.Node, src []byte) int {
	return cyclomaticOf(spec, n, src)
}

// FuncInfo describes one function found in a file.
type FuncInfo struct {
	Node       *sitter.Node
	Name       string
	Complexity int
}

// Functions returns every named function/method declaration with its name and
// cyclomatic complexity.
func Functions(spec langspec.Spec, root *sitter.Node, src []byte) []FuncInfo {
	var out []FuncInfo
	parse.Walk(root, func(n *sitter.Node) {
		if !spec.FuncDecl[n.Type()] {
			return
		}
		name := ""
		if id := n.ChildByFieldName(spec.NameField); id != nil {
			name = id.Content(src)
		}
		out = append(out, FuncInfo{Node: n, Name: name, Complexity: cyclomaticOf(spec, n, src)})
	})
	return out
}

// cognitiveOf computes a simplified cognitive complexity: control-flow
// structures cost 1 plus the current nesting depth, and each logical operator
// costs 1.
func cognitiveOf(spec langspec.Spec, root *sitter.Node, src []byte) int {
	var rec func(n *sitter.Node, nesting int) int
	rec = func(n *sitter.Node, nesting int) int {
		total := 0
		for i := 0; i < int(n.NamedChildCount()); i++ {
			c := n.NamedChild(i)
			switch {
			case spec.CognitiveControl[c.Type()]:
				total += 1 + nesting
				total += rec(c, nesting+1)
			case spec.IsLogical(c, src):
				total++
				total += rec(c, nesting)
			default:
				total += rec(c, nesting)
			}
		}
		return total
	}
	return rec(root, 0)
}

// Compute returns all file-level metrics for a parsed file.
func Compute(spec langspec.Spec, path string, root *sitter.Node, src []byte) domain.FileMetrics {
	codeLines := map[int]bool{}
	commentLines := map[int]bool{}

	parse.Walk(root, func(n *sitter.Node) {
		if n.ChildCount() != 0 {
			return // only leaf tokens carry line attribution
		}
		start := int(n.StartPoint().Row)
		if n.Type() == spec.CommentType {
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

	funcs := Functions(spec, root, src)
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
		CognitiveComplexity: cognitiveOf(spec, root, src),
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
	if src[len(src)-1] == '\n' {
		n-- // don't count a trailing newline as an extra empty line
	}
	return n
}
