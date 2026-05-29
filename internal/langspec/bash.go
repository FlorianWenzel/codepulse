package langspec

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/bash"

	"github.com/FlorianWenzel/codepulse/internal/lang"
)

// Bash returns the spec for the Bash grammar.
func Bash() Spec {
	return Spec{
		Lang:             lang.Bash,
		TS:               bash.GetLanguage(),
		Prefix:           "bash",
		Decision:         set("if_statement", "elif_clause", "for_statement", "while_statement", "case_item"),
		FuncDecl:         set("function_definition"),
		NameField:        "name",
		CognitiveControl: set("if_statement", "for_statement", "while_statement", "case_statement"),
		CommentTypes:     set("comment"),
		// Bash joins commands with &&/|| as list nodes, not a simple operator;
		// we count explicit control structures only.
		IsLogical: func(n *sitter.Node, src []byte) bool { return false },
	}
}
