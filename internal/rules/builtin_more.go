package rules

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"

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
	return []Rule{
		todoRuleQuery("cs", singleComment),
		{
			ID:        "cs:empty-catch",
			Name:      "Empty catch block swallows exceptions",
			Type:      domain.TypeBug,
			Severity:  domain.SevMajor,
			EffortMin: 10,
			Query:     `(catch_clause (block) @flag)`,
			Capture:   "flag",
			Predicate: func(n *sitter.Node, src []byte) (string, bool) {
				if n.NamedChildCount() > 0 {
					return "", false
				}
				return "Handle or log the exception instead of leaving an empty catch block.", true
			},
		},
		{
			ID:        "cs:weak-hash",
			Name:      "Weak cryptographic hash (MD5/SHA-1)",
			Type:      domain.TypeHotspot,
			Severity:  domain.SevMajor,
			EffortMin: 15,
			Query:     `(member_access_expression expression: (identifier) @t (#match? @t "^(MD5|SHA1|SHA1Managed|MD5CryptoServiceProvider)$")) @flag`,
			Capture:   "flag",
			Message:   "MD5/SHA-1 are weak; use SHA256 (and PBKDF2/bcrypt/argon2 for passwords).",
		},
		{
			ID:        "cs:process-start",
			Name:      "Process execution is security-sensitive",
			Type:      domain.TypeHotspot,
			Severity:  domain.SevMajor,
			EffortMin: 15,
			Query:     `(member_access_expression expression: (identifier) @o name: (identifier) @m (#eq? @o "Process") (#eq? @m "Start")) @flag`,
			Capture:   "flag",
			Message:   "Process.Start with untrusted input is command injection; pass arguments via ProcessStartInfo.ArgumentList and validate them.",
		},
		complexityRule(langspec.CSharp()),
	}
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
		{
			ID:        "kt:not-null-assertion",
			Name:      "Avoid the !! not-null assertion",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMajor,
			EffortMin: 10,
			Query:     `(postfix_expression) @flag`,
			Capture:   "flag",
			Predicate: func(n *sitter.Node, src []byte) (string, bool) {
				if !strings.HasSuffix(n.Content(src), "!!") {
					return "", false
				}
				return "The !! operator throws NullPointerException if the value is null; use ?., ?:, or a checked null path.", true
			},
		},
		{
			ID:        "kt:runtime-exec",
			Name:      "Runtime command execution is security-sensitive",
			Type:      domain.TypeHotspot,
			Severity:  domain.SevMajor,
			EffortMin: 15,
			Query:     `(navigation_expression (simple_identifier) @o (navigation_suffix (simple_identifier) @m) (#eq? @o "Runtime") (#eq? @m "getRuntime")) @flag`,
			Capture:   "flag",
			Message:   "Runtime.getRuntime().exec with untrusted input is command injection; use ProcessBuilder with an argument list and validate input.",
		},
		complexityRule(langspec.Kotlin()),
	}
}
