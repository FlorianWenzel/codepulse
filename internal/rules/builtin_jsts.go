package rules

import (
	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/langspec"
)

// jsLikeRules returns the rule set shared by JavaScript and TypeScript,
// namespaced by the spec's prefix (js / ts).
func jsLikeRules(spec langspec.Spec) []Rule {
	p := spec.Prefix
	return []Rule{
		{
			ID:        p + ":eval-usage",
			Name:      "Use of eval() executes arbitrary code",
			Type:      domain.TypeVulnerability,
			Severity:  domain.SevCritical,
			EffortMin: 20,
			Query:     `(call_expression function: (identifier) @fn (#eq? @fn "eval")) @flag`,
			Capture:   "flag",
			Message:   "Avoid eval(); it executes arbitrary code. Parse or dispatch explicitly instead.",
		},
		{
			ID:        p + ":debugger-statement",
			Name:      "Leftover debugger statement",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMajor,
			EffortMin: 5,
			Query:     `(debugger_statement) @flag`,
			Capture:   "flag",
			Message:   "Remove this debugger statement before committing.",
		},
		{
			ID:        p + ":child-process-exec",
			Name:      "Command execution is security-sensitive",
			Type:      domain.TypeHotspot,
			Severity:  domain.SevMajor,
			EffortMin: 10,
			Query:     `(call_expression function: (member_expression property: (property_identifier) @m (#eq? @m "exec"))) @flag`,
			Capture:   "flag",
			Message:   "Review this command execution: ensure inputs are trusted and not shell-injectable.",
		},
		{
			ID:        p + ":todo-comment",
			Name:      "Track and resolve TODO/FIXME comments",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevInfo,
			EffortMin: 5,
			Query:     `((comment) @flag (#match? @flag "(TODO|FIXME|XXX)"))`,
			Capture:   "flag",
			Message:   "Complete the task described by this TODO/FIXME marker.",
		},
		{
			ID:        p + ":console-usage",
			Name:      "Remove console statements",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMinor,
			EffortMin: 5,
			Query:     `(call_expression function: (member_expression object: (identifier) @o (#eq? @o "console"))) @flag`,
			Capture:   "flag",
			Message:   "Remove this console.* call, or use a proper logger.",
		},
		complexityRule(spec),
	}
}
