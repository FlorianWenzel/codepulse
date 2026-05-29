package rules

import (
	sitter "github.com/smacker/go-tree-sitter"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/langspec"
)

// goRules returns CodePulse's built-in Go rule set ("the CodePulse Way"
// starter profile). Each rule is deliberately low-false-positive.
func goRules() []Rule {
	return []Rule{
		{
			ID:        "go:panic-usage",
			Name:      "panic() should not be used for normal control flow",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMajor,
			EffortMin: 15,
			Query:     `(call_expression function: (identifier) @fn (#eq? @fn "panic")) @flag`,
			Capture:   "flag",
			Message:   "Avoid panic(); return an error to the caller instead.",
		},
		{
			ID:        "go:todo-comment",
			Name:      "Track and resolve TODO/FIXME comments",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevInfo,
			EffortMin: 5,
			Query:     `((comment) @flag (#match? @flag "(TODO|FIXME|XXX)"))`,
			Capture:   "flag",
			Message:   "Complete the task described by this TODO/FIXME marker.",
		},
		{
			ID:        "go:empty-block",
			Name:      "Empty blocks should be removed or documented",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMinor,
			EffortMin: 5,
			Query:     `(block) @flag`,
			Capture:   "flag",
			Predicate: func(n *sitter.Node, src []byte) (string, bool) {
				if n.NamedChildCount() > 0 {
					return "", false
				}
				return "Remove this empty block, or add a comment explaining why it is empty.", true
			},
		},
		complexityRule(langspec.Go()),
	}
}
