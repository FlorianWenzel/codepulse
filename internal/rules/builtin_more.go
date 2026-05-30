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

func cppRules() []Rule {
	return append([]Rule{todoRule("cpp")}, append(cFamilySecurityRules("cpp"), complexityRule(langspec.Cpp()))...)
}
func csRules() []Rule {
	return []Rule{todoRuleQuery("cs", singleComment), complexityRule(langspec.CSharp())}
}
func phpRules() []Rule {
	return []Rule{
		todoRule("php"),
		{
			ID:        "php:eval-usage",
			Name:      "Use of eval() executes arbitrary code",
			Type:      domain.TypeVulnerability,
			Severity:  domain.SevCritical,
			EffortMin: 20,
			Query:     `(function_call_expression function: (name) @fn (#eq? @fn "eval")) @flag`,
			Capture:   "flag",
			Message:   "Avoid eval(); it executes arbitrary PHP. Parse/validate input or dispatch explicitly.",
		},
		{
			ID:        "php:exec-usage",
			Name:      "Shell command execution is security-sensitive",
			Type:      domain.TypeVulnerability,
			Severity:  domain.SevCritical,
			EffortMin: 20,
			Query:     `(function_call_expression function: (name) @fn (#match? @fn "^(system|exec|shell_exec|passthru|proc_open|popen)$")) @flag`,
			Capture:   "flag",
			Message:   "Shell execution with untrusted input is command injection; use escapeshellarg/escapeshellcmd or avoid the shell.",
		},
		{
			ID:        "php:weak-hash",
			Name:      "Weak cryptographic hash (MD5/SHA-1)",
			Type:      domain.TypeHotspot,
			Severity:  domain.SevMajor,
			EffortMin: 15,
			Query:     `(function_call_expression function: (name) @fn (#match? @fn "^(md5|sha1)$")) @flag`,
			Capture:   "flag",
			Message:   "MD5/SHA-1 are weak; use hash('sha256', ...) (and password_hash() for passwords).",
		},
		complexityRule(langspec.PHP()),
	}
}
func ktRules() []Rule {
	return []Rule{
		todoRuleQuery("kt", `([(line_comment) (multiline_comment)] @flag (#match? @flag "(TODO|FIXME|XXX)"))`),
		complexityRule(langspec.Kotlin()),
	}
}
