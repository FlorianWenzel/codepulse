package rules

import (
	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/langspec"
)

// rubyRules returns CodePulse's built-in Ruby rule set.
func rubyRules() []Rule {
	return []Rule{
		{
			ID:        "ruby:todo-comment",
			Name:      "Track and resolve TODO/FIXME comments",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevInfo,
			EffortMin: 5,
			Query:     `((comment) @flag (#match? @flag "(TODO|FIXME|XXX)"))`,
			Capture:   "flag",
			Message:   "Complete the task described by this TODO/FIXME marker.",
		},
		{
			ID:        "ruby:eval-usage",
			Name:      "Use of eval executes arbitrary code",
			Type:      domain.TypeVulnerability,
			Severity:  domain.SevCritical,
			EffortMin: 20,
			Query:     `(call method: (identifier) @m (#match? @m "^(eval|instance_eval|class_eval|module_eval)$")) @flag`,
			Capture:   "flag",
			Message:   "Avoid eval/instance_eval on untrusted input; it executes arbitrary Ruby.",
		},
		{
			ID:        "ruby:command-exec",
			Name:      "Shell command execution is security-sensitive",
			Type:      domain.TypeVulnerability,
			Severity:  domain.SevCritical,
			EffortMin: 20,
			Query:     `[(call method: (identifier) @m (#match? @m "^(system|exec|spawn|syscall)$")) (subshell)] @flag`,
			Capture:   "flag",
			Message:   "Shell execution (system/exec/backticks) with untrusted input is command injection; pass an argument array, not a string.",
		},
		{
			ID:        "ruby:weak-hash",
			Name:      "Weak cryptographic hash (MD5/SHA-1)",
			Type:      domain.TypeHotspot,
			Severity:  domain.SevMajor,
			EffortMin: 15,
			Query:     `(scope_resolution scope: (constant) @s name: (constant) @n (#eq? @s "Digest") (#match? @n "^(MD5|SHA1)$")) @flag`,
			Capture:   "flag",
			Message:   "MD5/SHA-1 are weak; use Digest::SHA256+ (and bcrypt/argon2 for passwords).",
		},
		complexityRule(langspec.Ruby()),
	}
}
