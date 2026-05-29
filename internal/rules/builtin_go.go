package rules

import (
	sitter "github.com/smacker/go-tree-sitter"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/langspec"
)

// goRules returns CodePulse's built-in Go rule set ("the CodePulse Way"
// starter profile). Each rule is deliberately low-false-positive.
func goRules() []Rule {
	return []Rule{
		{
			ID:        "go:panic-usage",
			Name:      "panic() should not be used for normal control flow",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMajor,
			EffortMin: 15,
			Query:     `(call_expression function: (identifier) @fn (#eq? @fn "panic")) @flag`,
			Capture:   "flag",
			Message:   "Avoid panic(); return an error to the caller instead.",
		},
		{
			ID:        "go:todo-comment",
			Name:      "Track and resolve TODO/FIXME comments",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevInfo,
			EffortMin: 5,
			Query:     `((comment) @flag (#match? @flag "(TODO|FIXME|XXX)"))`,
			Capture:   "flag",
			Message:   "Complete the task described by this TODO/FIXME marker.",
		},
		{
			ID:        "go:empty-block",
			Name:      "Empty blocks should be removed or documented",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMinor,
			EffortMin: 5,
			Query:     `(block) @flag`,
			Capture:   "flag",
			Predicate: func(n *sitter.Node, src []byte) (string, bool) {
				if n.NamedChildCount() > 0 {
					return "", false
				}
				return "Remove this empty block, or add a comment explaining why it is empty.", true
			},
		},
		{
			ID:        "go:exec-command",
			Name:      "OS command execution is security-sensitive",
			Type:      domain.TypeHotspot,
			Severity:  domain.SevMajor,
			EffortMin: 10,
			Query:     `(call_expression function: (selector_expression field: (field_identifier) @m (#eq? @m "Command"))) @flag`,
			Capture:   "flag",
			Message:   "Review this command execution: ensure arguments are trusted and not attacker-controlled.",
		},
		{
			ID:        "go:weak-hash",
			Name:      "Weak cryptographic hash (MD5/SHA-1)",
			Type:      domain.TypeHotspot,
			Severity:  domain.SevMajor,
			EffortMin: 15,
			Query:     `(call_expression function: (selector_expression operand: (identifier) @pkg field: (field_identifier) @fn) (#match? @pkg "^(md5|sha1)$") (#eq? @fn "New")) @flag`,
			Capture:   "flag",
			Message:   "MD5/SHA-1 are weak; use SHA-256+ for security-sensitive hashing.",
		},
		{
			ID:        "go:debug-print",
			Name:      "Remove debug print statements",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMinor,
			EffortMin: 5,
			Query:     `(call_expression function: (selector_expression operand: (identifier) @pkg field: (field_identifier) @fn) (#eq? @pkg "fmt") (#match? @fn "^(Print|Printf|Println)$")) @flag`,
			Capture:   "flag",
			Message:   "Remove this fmt debug print, or use a structured logger.",
		},
		{
			ID:        "go:context-todo",
			Name:      "context.TODO() should be replaced before release",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMinor,
			EffortMin: 10,
			Query:     `(call_expression function: (selector_expression operand: (identifier) @p field: (field_identifier) @f) (#eq? @p "context") (#eq? @f "TODO")) @flag`,
			Capture:   "flag",
			Message:   "Replace context.TODO() with a real context (e.g. the request's context).",
		},
		{
			ID:        "go:error-new-fmt",
			Name:      "Use fmt.Errorf instead of errors.New(fmt.Sprintf(...))",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMinor,
			EffortMin: 5,
			Query: `(call_expression
				function: (selector_expression operand: (identifier) @pkg field: (field_identifier) @fn)
				arguments: (argument_list (call_expression
					function: (selector_expression operand: (identifier) @ipkg field: (field_identifier) @ifn)))
				(#eq? @pkg "errors") (#eq? @fn "New") (#eq? @ipkg "fmt") (#eq? @ifn "Sprintf")) @flag`,
			Capture: "flag",
			Message: "Use fmt.Errorf(...) instead of errors.New(fmt.Sprintf(...)).",
		},
		{
			ID:        "go:os-exit",
			Name:      "os.Exit() should not be used in library code",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMajor,
			EffortMin: 15,
			Query:     `(call_expression function: (selector_expression operand: (identifier) @p field: (field_identifier) @f) (#eq? @p "os") (#eq? @f "Exit")) @flag`,
			Capture:   "flag",
			Message:   "Avoid os.Exit() outside main(); it skips deferred cleanup. Return an error instead.",
		},
		complexityRule(langspec.Go()),
	}
}
