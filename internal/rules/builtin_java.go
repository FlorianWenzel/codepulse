package rules

import (
	sitter "github.com/smacker/go-tree-sitter"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/langspec"
)

// javaRules returns CodePulse's built-in Java rule set.
func javaRules() []Rule {
	return []Rule{
		{
			ID:        "java:todo-comment",
			Name:      "Track and resolve TODO/FIXME comments",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevInfo,
			EffortMin: 5,
			Query:     `([(line_comment) (block_comment)] @flag (#match? @flag "(TODO|FIXME|XXX)"))`,
			Capture:   "flag",
			Message:   "Complete the task described by this TODO/FIXME marker.",
		},
		{
			ID:        "java:empty-catch",
			Name:      "Empty catch block swallows exceptions",
			Type:      domain.TypeBug,
			Severity:  domain.SevMajor,
			EffortMin: 10,
			Query:     `(catch_clause body: (block) @flag)`,
			Capture:   "flag",
			Predicate: func(n *sitter.Node, src []byte) (string, bool) {
				if n.NamedChildCount() > 0 {
					return "", false
				}
				return "Handle or log the exception instead of leaving an empty catch block.", true
			},
		},
		{
			ID:        "java:system-exit",
			Name:      "System.exit() should not be used in library code",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMajor,
			EffortMin: 15,
			Query:     `(method_invocation object: (identifier) @o name: (identifier) @m (#eq? @o "System") (#eq? @m "exit")) @flag`,
			Capture:   "flag",
			Message:   "Avoid System.exit(); throw or return to let the caller decide.",
		},
		{
			ID:        "java:process-exec",
			Name:      "Process execution is security-sensitive",
			Type:      domain.TypeHotspot,
			Severity:  domain.SevMajor,
			EffortMin: 10,
			Query:     `(method_invocation name: (identifier) @m (#eq? @m "exec")) @flag`,
			Capture:   "flag",
			Message:   "Review this process execution: ensure the command and arguments are trusted.",
		},
		complexityRule(langspec.Java()),
	}
}
