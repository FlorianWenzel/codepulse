package langspec

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/ruby"

	"github.com/FlorianWenzel/codepulse/internal/lang"
)

// Ruby returns the spec for the Ruby grammar.
func Ruby() Spec {
	return Spec{
		Lang:             lang.Ruby,
		TS:               ruby.GetLanguage(),
		Prefix:           "ruby",
		Decision:         set("if", "elsif", "while", "until", "for", "when", "rescue"),
		FuncDecl:         set("method", "singleton_method"),
		NameField:        "name",
		CognitiveControl: set("if", "while", "until", "for", "case"),
		CommentTypes:     set("comment"),
		IsLogical: func(n *sitter.Node, src []byte) bool {
			if n.Type() != "binary" {
				return false
			}
			op := n.ChildByFieldName("operator")
			if op == nil {
				return false
			}
			t := op.Content(src)
			return t == "&&" || t == "||" || t == "and" || t == "or"
		},
	}
}
