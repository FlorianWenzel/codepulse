package rules

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/langspec"
)

func scalaRules() []Rule {
	return []Rule{
		todoRule("scala"),
		{
			ID:        "scala:null-usage",
			Name:      "Avoid null; use Option",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMajor,
			EffortMin: 10,
			Query:     `(null_literal) @flag`,
			Capture:   "flag",
			Message:   "Avoid null in Scala; model absence with Option (Some/None) to prevent NullPointerExceptions.",
		},
		{
			ID:        "scala:asinstanceof",
			Name:      "Unsafe cast with asInstanceOf",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMajor,
			EffortMin: 15,
			Query:     `(field_expression (identifier) @m (#eq? @m "asInstanceOf")) @flag`,
			Capture:   "flag",
			Message:   "asInstanceOf throws ClassCastException at runtime; use pattern matching (match/case) for safe, checked casts.",
		},
		complexityRule(langspec.Scala()),
	}
}
func swiftRules() []Rule {
	return []Rule{
		todoRuleQuery("swift", `([(comment) (multiline_comment)] @flag (#match? @flag "(TODO|FIXME|XXX)"))`),
		{
			ID:        "swift:force-unwrap",
			Name:      "Avoid force-unwrapping optionals (!)",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMajor,
			EffortMin: 10,
			Query:     `(postfix_expression (bang)) @flag`,
			Capture:   "flag",
			Message:   "Force-unwrapping (!) crashes at runtime if the optional is nil; use if let, guard let, or ?? instead.",
		},
		{
			ID:        "swift:force-try",
			Name:      "Avoid force-try (try!)",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMajor,
			EffortMin: 10,
			Query:     `(try_operator) @flag`,
			Capture:   "flag",
			Predicate: func(n *sitter.Node, src []byte) (string, bool) {
				if strings.TrimSpace(n.Content(src)) != "try!" {
					return "", false
				}
				return "try! crashes if the call throws; use do/try/catch or try? to handle the error.", true
			},
		},
		complexityRule(langspec.Swift()),
	}
}
