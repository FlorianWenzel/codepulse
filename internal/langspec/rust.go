package langspec

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/rust"

	"github.com/FlorianWenzel/codepulse/internal/lang"
)

// Rust returns the spec for the Rust grammar.
func Rust() Spec {
	return Spec{
		Lang:             lang.Rust,
		TS:               rust.GetLanguage(),
		Prefix:           "rust",
		Decision:         set("if_expression", "while_expression", "for_expression", "loop_expression", "match_arm"),
		FuncDecl:         set("function_item"),
		NameField:        "name",
		CognitiveControl: set("if_expression", "while_expression", "for_expression", "loop_expression", "match_expression"),
		CommentTypes:     set("line_comment", "block_comment"),
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
