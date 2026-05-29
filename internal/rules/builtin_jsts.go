package rules

import (
	sitter "github.com/smacker/go-tree-sitter"

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
			ID:        p + ":inner-html",
			Name:      "Assigning to innerHTML can introduce XSS",
			Type:      domain.TypeHotspot,
			Severity:  domain.SevMajor,
			EffortMin: 15,
			Query:     `(assignment_expression left: (member_expression property: (property_identifier) @prop (#eq? @prop "innerHTML"))) @flag`,
			Capture:   "flag",
			Message:   "Review this innerHTML assignment for XSS; prefer textContent or sanitize input.",
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
		{
			ID:        p + ":loose-equality",
			Name:      "Use strict equality (=== / !==)",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMinor,
			EffortMin: 5,
			Query:     `(binary_expression) @flag`,
			Capture:   "flag",
			Predicate: func(n *sitter.Node, src []byte) (string, bool) {
				op := n.ChildByFieldName("operator")
				if op == nil {
					return "", false
				}
				if t := op.Content(src); t == "==" || t == "!=" {
					return "Use strict equality (=== / !==) to avoid type coercion.", true
				}
				return "", false
			},
		},
		{
			ID:        p + ":var-declaration",
			Name:      "Prefer let/const over var",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMinor,
			EffortMin: 5,
			Query:     `(variable_declaration) @flag`,
			Capture:   "flag",
			Message:   "Use let or const instead of var (block scoping).",
		},
		{
			ID:        p + ":document-write",
			Name:      "document.write enables XSS and blocks parsing",
			Type:      domain.TypeHotspot,
			Severity:  domain.SevMajor,
			EffortMin: 15,
			Query:     `(call_expression function: (member_expression object: (identifier) @o property: (property_identifier) @prop) (#eq? @o "document") (#eq? @prop "write")) @flag`,
			Capture:   "flag",
			Message:   "Avoid document.write; build DOM nodes / set textContent and sanitize input.",
		},
		{
			ID:        p + ":alert",
			Name:      "Leftover alert()/confirm()/prompt()",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMinor,
			EffortMin: 5,
			Query:     `(call_expression function: (identifier) @fn (#match? @fn "^(alert|confirm|prompt)$")) @flag`,
			Capture:   "flag",
			Message:   "Remove this alert/confirm/prompt; use proper UI.",
		},
		{
			ID:        p + ":throw-literal",
			Name:      "Throw an Error, not a literal",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMinor,
			EffortMin: 5,
			Query:     `(throw_statement [(string) (template_string) (number)]) @flag`,
			Capture:   "flag",
			Message:   "Throw an Error object (preserves stack/type), not a string/number literal.",
		},
		{
			ID:        p + ":no-with",
			Name:      "Avoid the with statement",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMajor,
			EffortMin: 15,
			Query:     `(with_statement) @flag`,
			Capture:   "flag",
			Message:   "Avoid `with`; it makes scope ambiguous and is disallowed in strict mode.",
		},
		{
			ID:        p + ":no-new-wrappers",
			Name:      "Don't use primitive wrapper constructors",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMinor,
			EffortMin: 5,
			Query:     `(new_expression constructor: (identifier) @c (#match? @c "^(String|Number|Boolean)$")) @flag`,
			Capture:   "flag",
			Message:   "new String/Number/Boolean creates objects, not primitives; call them without `new`.",
		},
		jsTaintEvalRule(p),
		jsTaintXSSRule(p),
		jsTaintExecRule(p),
		complexityRule(spec),
	}
}
