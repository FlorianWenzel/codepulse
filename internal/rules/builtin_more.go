package rules

import (
	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/langspec"
)

// todoRuleQuery builds a TODO/FIXME rule with a language-specific comment query.
func todoRuleQuery(prefix, query string) Rule {
	return Rule{
		ID:        prefix + ":todo-comment",
		Name:      "Track and resolve TODO/FIXME comments",
		Type:      domain.TypeCodeSmell,
		Severity:  domain.SevInfo,
		EffortMin: 5,
		Query:     query,
		Capture:   "flag",
		Message:   "Complete the task described by this TODO/FIXME marker.",
	}
}

const singleComment = `((comment) @flag (#match? @flag "(TODO|FIXME|XXX)"))`

func cppRules() []Rule { return []Rule{todoRule("cpp"), complexityRule(langspec.Cpp())} }
func csRules() []Rule {
	return []Rule{todoRuleQuery("cs", singleComment), complexityRule(langspec.CSharp())}
}
func phpRules() []Rule { return []Rule{todoRule("php"), complexityRule(langspec.PHP())} }
func ktRules() []Rule {
	return []Rule{
		todoRuleQuery("kt", `([(line_comment) (multiline_comment)] @flag (#match? @flag "(TODO|FIXME|XXX)"))`),
		complexityRule(langspec.Kotlin()),
	}
}
