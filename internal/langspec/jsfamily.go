package langspec

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/typescript/typescript"

	"github.com/FlorianWenzel/codepulse/internal/lang"
)

// jsFamily builds a Spec for JavaScript/TypeScript, which share node kinds
// (TypeScript's grammar is a superset of JavaScript's).
func jsFamily(l lang.Language, prefix string, ts *sitter.Language) Spec {
	return Spec{
		Lang:      l,
		TS:        ts,
		Prefix:    prefix,
		Decision:  set("if_statement", "for_statement", "for_in_statement", "while_statement", "do_statement", "catch_clause", "ternary_expression", "switch_case"),
		FuncDecl:  set("function_declaration", "method_definition"),
		NameField: "name",
		CognitiveControl: set("if_statement", "for_statement", "for_in_statement",
			"while_statement", "do_statement", "switch_statement"),
		CommentType: "comment",
		IsLogical: func(n *sitter.Node, src []byte) bool {
			if n.Type() != "binary_expression" {
				return false
			}
			op := n.ChildByFieldName("operator")
			if op == nil {
				return false
			}
			t := op.Content(src)
			return t == "&&" || t == "||" || t == "??"
		},
	}
}

// JavaScript returns the spec for the JavaScript grammar.
func JavaScript() Spec { return jsFamily(lang.JavaScript, "js", javascript.GetLanguage()) }

// TypeScript returns the spec for the TypeScript grammar.
func TypeScript() Spec { return jsFamily(lang.TypeScript, "ts", typescript.GetLanguage()) }
