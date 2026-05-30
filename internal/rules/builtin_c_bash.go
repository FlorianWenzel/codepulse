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

// cFamilySecurityRules returns the C/C++ security rules shared by both
// languages (they share tree-sitter call_expression shape).
func cFamilySecurityRules(prefix string) []Rule {
	return []Rule{
		{
			ID:        prefix + ":unsafe-cstring-fn",
			Name:      "Unsafe C string function (buffer overflow)",
			Type:      domain.TypeHotspot,
			Severity:  domain.SevMajor,
			EffortMin: 20,
			Query:     `(call_expression function: (identifier) @fn (#match? @fn "^(gets|strcpy|strcat|sprintf|vsprintf|stpcpy)$")) @flag`,
			Capture:   "flag",
			Message:   "This function writes without a size bound; a long input overflows the buffer. Use the bounded variant (snprintf, strncpy/strlcpy, fgets).",
		},
		{
			ID:        prefix + ":system-exec",
			Name:      "Shell command execution is security-sensitive",
			Type:      domain.TypeHotspot,
			Severity:  domain.SevMajor,
			EffortMin: 15,
			Query:     `(call_expression function: (identifier) @fn (#match? @fn "^(system|popen)$")) @flag`,
			Capture:   "flag",
			Message:   "system/popen run a shell; untrusted input enables command injection. Use exec* with an argument vector and validated input.",
		},
	}
}

// cRules / bashRules: starter sets (+ security rules for C).
func cRules() []Rule {
	return append([]Rule{todoRule("c")}, append(cFamilySecurityRules("c"), complexityRule(langspec.C()))...)
}
func bashRules() []Rule { return []Rule{todoRule("bash"), complexityRule(langspec.Bash())} }
