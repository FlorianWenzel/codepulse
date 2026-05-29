package langspec

import (
	sitter "github.com/smacker/go-tree-sitter"
	cgrammar "github.com/smacker/go-tree-sitter/c"

	"github.com/FlorianWenzel/codepulse/internal/lang"
)

// C returns the spec for the C grammar.
func C() Spec {
	return Spec{
		Lang:             lang.C,
		TS:               cgrammar.GetLanguage(),
		Prefix:           "c",
		Decision:         set("if_statement", "for_statement", "while_statement", "do_statement", "case_statement"),
		FuncDecl:         set("function_definition"),
		NameField:        "declarator",
		CognitiveControl: set("if_statement", "for_statement", "while_statement", "do_statement", "switch_statement"),
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
