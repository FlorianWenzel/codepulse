package rules

import "github.com/FlorianWenzel/codepulse/internal/langspec"

func scalaRules() []Rule { return []Rule{todoRule("scala"), complexityRule(langspec.Scala())} }
func swiftRules() []Rule {
	return []Rule{
		todoRuleQuery("swift", `([(comment) (multiline_comment)] @flag (#match? @flag "(TODO|FIXME|XXX)"))`),
		complexityRule(langspec.Swift()),
	}
}
