package rules

import (
	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/langspec"
)

func todoRule(prefix string) Rule {
	return Rule{
		ID:        prefix + ":todo-comment",
		Name:      "Track and resolve TODO/FIXME comments",
		Type:      domain.TypeCodeSmell,
		Severity:  domain.SevInfo,
		EffortMin: 5,
		Query:     `((comment) @flag (#match? @flag "(TODO|FIXME|XXX)"))`,
		Capture:   "flag",
		Message:   "Complete the task described by this TODO/FIXME marker.",
	}
}

// cRules / bashRules: starter sets (TODO + complexity).
func cRules() []Rule    { return []Rule{todoRule("c"), complexityRule(langspec.C())} }
func bashRules() []Rule { return []Rule{todoRule("bash"), complexityRule(langspec.Bash())} }
