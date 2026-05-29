package langspec

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/scala"
	"github.com/smacker/go-tree-sitter/swift"

	"github.com/FlorianWenzel/codepulse/internal/lang"
)

// Scala returns the spec for the Scala grammar.
func Scala() Spec {
	return Spec{
		Lang: lang.Scala, TS: scala.GetLanguage(), Prefix: "scala",
		Decision:         set("if_expression", "while_expression", "for_expression", "case_clause", "catch_clause"),
		FuncDecl:         set("function_definition"),
		NameField:        "name",
		CognitiveControl: set("if_expression", "while_expression", "for_expression", "match_expression"),
		CommentTypes:     set("comment", "block_comment"),
		IsLogical: func(n *sitter.Node, src []byte) bool {
			if n.Type() != "infix_expression" {
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

// Swift returns the spec for the Swift grammar.
func Swift() Spec {
	return Spec{
		Lang: lang.Swift, TS: swift.GetLanguage(), Prefix: "swift",
		Decision:         set("if_statement", "while_statement", "for_statement", "guard_statement", "catch_clause"),
		FuncDecl:         set("function_declaration"),
		NameField:        "name",
		CognitiveControl: set("if_statement", "while_statement", "for_statement", "switch_statement"),
		CommentTypes:     set("comment", "multiline_comment"),
		IsLogical: func(n *sitter.Node, src []byte) bool {
			return n.Type() == "conjunction_expression" || n.Type() == "disjunction_expression"
		},
	}
}
