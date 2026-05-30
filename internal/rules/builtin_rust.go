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
		{
			ID:        "rust:unsafe-block",
			Name:      "unsafe block bypasses Rust's safety guarantees",
			Type:      domain.TypeHotspot,
			Severity:  domain.SevMajor,
			EffortMin: 20,
			Query:     `(unsafe_block) @flag`,
			Capture:   "flag",
			Message:   "unsafe disables Rust's memory-safety checks; review for UB (aliasing, bounds, lifetimes) and document the invariants that make it sound.",
		},
		{
			ID:        "rust:panic-macro",
			Name:      "panic!/unreachable! aborts instead of returning an error",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMajor,
			EffortMin: 15,
			Query:     `(macro_invocation macro: (identifier) @m (#match? @m "^(panic|unreachable)$")) @flag`,
			Capture:   "flag",
			Message:   "panic!/unreachable! aborts the thread; return a Result or handle the case instead (reserve panics for truly impossible states).",
		},
		complexityRule(langspec.Rust()),
	}
}
