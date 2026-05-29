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
		{
			ID:        "java:print-stacktrace",
			Name:      "Don't expose stack traces via printStackTrace()",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMinor,
			EffortMin: 10,
			Query:     `(method_invocation name: (identifier) @m (#eq? @m "printStackTrace")) @flag`,
			Capture:   "flag",
			Message:   "Log the exception through a logger instead of printStackTrace().",
		},
		{
			ID:        "java:system-print",
			Name:      "Remove System.out/err debug prints",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMinor,
			EffortMin: 5,
			Query:     `(method_invocation object: (field_access object: (identifier) @a field: (identifier) @b) name: (identifier) @m (#eq? @a "System") (#match? @b "^(out|err)$") (#match? @m "^(print|println|printf)$")) @flag`,
			Capture:   "flag",
			Message:   "Use a logger instead of System.out/System.err.",
		},
		{
			ID:        "java:catch-generic",
			Name:      "Catch specific exceptions, not Exception/Throwable",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMajor,
			EffortMin: 10,
			Query:     `(catch_clause (catch_formal_parameter (catch_type (type_identifier) @t (#match? @t "^(Exception|Throwable)$")))) @flag`,
			Capture:   "flag",
			Message:   "Catch a specific exception type rather than Exception/Throwable.",
		},
		complexityRule(langspec.Java()),
	}
}
