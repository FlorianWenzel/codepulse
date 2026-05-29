package langspec

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/cpp"
	"github.com/smacker/go-tree-sitter/csharp"
	"github.com/smacker/go-tree-sitter/kotlin"
	"github.com/smacker/go-tree-sitter/php"

	"github.com/FlorianWenzel/codepulse/internal/lang"
)

// binaryLogical returns an IsLogical for C-family grammars whose binary node is
// named nodeType and whose operator field holds && / ||.
func binaryLogical(nodeType string) func(*sitter.Node, []byte) bool {
	return func(n *sitter.Node, src []byte) bool {
		if n.Type() != nodeType {
			return false
		}
		op := n.ChildByFieldName("operator")
		if op == nil {
			return false
		}
		t := op.Content(src)
		return t == "&&" || t == "||"
	}
}

// Cpp returns the spec for the C++ grammar.
func Cpp() Spec {
	return Spec{
		Lang: lang.Cpp, TS: cpp.GetLanguage(), Prefix: "cpp",
		Decision:         set("if_statement", "for_statement", "while_statement", "do_statement", "case_statement", "catch_clause"),
		FuncDecl:         set("function_definition"),
		NameField:        "declarator",
		CognitiveControl: set("if_statement", "for_statement", "while_statement", "do_statement", "switch_statement"),
		CommentTypes:     set("comment"),
		IsLogical:        binaryLogical("binary_expression"),
	}
}

// CSharp returns the spec for the C# grammar.
func CSharp() Spec {
	return Spec{
		Lang: lang.CSharp, TS: csharp.GetLanguage(), Prefix: "cs",
		Decision:         set("if_statement", "for_statement", "for_each_statement", "while_statement", "do_statement", "switch_section", "catch_clause", "conditional_expression"),
		FuncDecl:         set("method_declaration"),
		NameField:        "name",
		CognitiveControl: set("if_statement", "for_statement", "for_each_statement", "while_statement", "do_statement", "switch_statement"),
		CommentTypes:     set("comment"),
		IsLogical:        binaryLogical("binary_expression"),
	}
}

// PHP returns the spec for the PHP grammar.
func PHP() Spec {
	return Spec{
		Lang: lang.PHP, TS: php.GetLanguage(), Prefix: "php",
		Decision:         set("if_statement", "for_statement", "foreach_statement", "while_statement", "do_statement", "case_statement", "catch_clause"),
		FuncDecl:         set("function_definition", "method_declaration"),
		NameField:        "name",
		CognitiveControl: set("if_statement", "for_statement", "foreach_statement", "while_statement", "do_statement", "switch_statement"),
		CommentTypes:     set("comment"),
		IsLogical:        binaryLogical("binary_expression"),
	}
}

// Kotlin returns the spec for the Kotlin grammar.
func Kotlin() Spec {
	return Spec{
		Lang: lang.Kotlin, TS: kotlin.GetLanguage(), Prefix: "kt",
		Decision:         set("if_expression", "for_statement", "while_statement", "do_while_statement", "when_entry", "catch_block"),
		FuncDecl:         set("function_declaration"),
		NameField:        "name",
		CognitiveControl: set("if_expression", "for_statement", "while_statement", "do_while_statement", "when_expression"),
		CommentTypes:     set("line_comment", "multiline_comment"),
		// Kotlin represents && / || as dedicated node types.
		IsLogical: func(n *sitter.Node, src []byte) bool {
			return n.Type() == "conjunction_expression" || n.Type() == "disjunction_expression"
		},
	}
}
