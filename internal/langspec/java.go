package langspec

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/java"

	"github.com/FlorianWenzel/codepulse/internal/lang"
)

// Java returns the spec for the Java grammar.
func Java() Spec {
	return Spec{
		Lang:      lang.Java,
		TS:        java.GetLanguage(),
		Prefix:    "java",
		Decision:  set("if_statement", "for_statement", "enhanced_for_statement", "while_statement", "do_statement", "catch_clause", "ternary_expression", "switch_label"),
		FuncDecl:  set("method_declaration", "constructor_declaration"),
		NameField: "name",
		CognitiveControl: set("if_statement", "for_statement", "enhanced_for_statement",
			"while_statement", "do_statement", "switch_expression", "switch_statement"),
		CommentTypes: set("line_comment", "block_comment"),
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
