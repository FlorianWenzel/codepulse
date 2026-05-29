// Package langspec maps each supported language to the concrete tree-sitter
// node kinds that the language-agnostic metrics and rules code needs. Adding a
// language is mostly a matter of adding a Spec here plus its rule queries.
package langspec

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/python"

	"github.com/FlorianWenzel/codepulse/internal/lang"
)

// Spec describes one language's grammar to the analysis core.
type Spec struct {
	Lang lang.Language
	TS   *sitter.Language
	// Prefix is the rule-id namespace for this language (e.g. "go", "py").
	Prefix string

	// Decision lists node types that add a branch to cyclomatic complexity
	// (excluding logical operators, which IsLogical handles).
	Decision map[string]bool
	// FuncDecl lists node types that are named function/method declarations.
	FuncDecl map[string]bool
	// NameField is the field name holding a function's name node.
	NameField string
	// CognitiveControl lists node types that add a cognitive-complexity
	// nesting level.
	CognitiveControl map[string]bool
	// CommentTypes is the set of node types that are comments.
	CommentTypes map[string]bool
	// IsLogical reports whether a node is a short-circuit logical operator
	// (each one adds 1 to cyclomatic and cognitive complexity).
	IsLogical func(n *sitter.Node, src []byte) bool
}

// IsComment reports whether a node type is a comment in this language.
func (s Spec) IsComment(t string) bool { return s.CommentTypes[t] }

func set(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

// Go returns the spec for the Go grammar.
func Go() Spec {
	return Spec{
		Lang:             lang.Go,
		TS:               golang.GetLanguage(),
		Prefix:           "go",
		Decision:         set("if_statement", "for_statement", "expression_case", "type_case", "communication_case"),
		FuncDecl:         set("function_declaration", "method_declaration"),
		NameField:        "name",
		CognitiveControl: set("if_statement", "for_statement", "expression_switch_statement", "type_switch_statement", "select_statement"),
		CommentTypes:     set("comment"),
		IsLogical: func(n *sitter.Node, src []byte) bool {
			if n.Type() != "binary_expression" {
				return false
			}
			op := n.ChildByFieldName("operator")
			if op == nil {
				return false
			}
			t := op.Content(src)
			return t == "&&" || t == "||"
		},
	}
}

// Python returns the spec for the Python grammar.
func Python() Spec {
	return Spec{
		Lang:             lang.Python,
		TS:               python.GetLanguage(),
		Prefix:           "py",
		Decision:         set("if_statement", "elif_clause", "for_statement", "while_statement", "except_clause", "case_clause", "conditional_expression"),
		FuncDecl:         set("function_definition"),
		NameField:        "name",
		CognitiveControl: set("if_statement", "for_statement", "while_statement", "match_statement"),
		CommentTypes:     set("comment"),
		// In tree-sitter-python, `and`/`or` are a single boolean_operator node.
		IsLogical: func(n *sitter.Node, src []byte) bool {
			return n.Type() == "boolean_operator"
		},
	}
}

// For returns the spec for a language, and whether one exists.
func For(l lang.Language) (Spec, bool) {
	switch l {
	case lang.Go:
		return Go(), true
	case lang.Python:
		return Python(), true
	case lang.JavaScript:
		return JavaScript(), true
	case lang.TypeScript:
		return TypeScript(), true
	case lang.Java:
		return Java(), true
	case lang.Ruby:
		return Ruby(), true
	case lang.Rust:
		return Rust(), true
	case lang.C:
		return C(), true
	case lang.Bash:
		return Bash(), true
	default:
		return Spec{}, false
	}
}
