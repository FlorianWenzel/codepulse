package rules

import (
	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/langspec"
)

// rustRules returns CodePulse's built-in Rust rule set.
func rustRules() []Rule {
	return []Rule{
		{
			ID:        "rust:todo-comment",
			Name:      "Track and resolve TODO/FIXME comments",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevInfo,
			EffortMin: 5,
			Query:     `([(line_comment) (block_comment)] @flag (#match? @flag "(TODO|FIXME|XXX)"))`,
			Capture:   "flag",
			Message:   "Complete the task described by this TODO/FIXME marker.",
		},
		{
			ID:        "rust:unwrap",
			Name:      "Avoid .unwrap(); handle the error or None case",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMinor,
			EffortMin: 10,
			Query:     `(call_expression function: (field_expression field: (field_identifier) @m (#eq? @m "unwrap"))) @flag`,
			Capture:   "flag",
			Message:   "Avoid .unwrap(); handle the Result/Option explicitly.",
		},
		complexityRule(langspec.Rust()),
	}
}
