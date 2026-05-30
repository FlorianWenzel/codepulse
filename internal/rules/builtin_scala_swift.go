package rules

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/langspec"
)

func scalaRules() []Rule { return []Rule{todoRule("scala"), complexityRule(langspec.Scala())} }
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
