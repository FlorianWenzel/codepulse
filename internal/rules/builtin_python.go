package rules

import (
	sitter "github.com/smacker/go-tree-sitter"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/langspec"
)

// pythonRules returns CodePulse's built-in Python rule set.
func pythonRules() []Rule {
	return []Rule{
		{
			ID:        "py:exec-eval",
			Name:      "Use of eval()/exec() executes arbitrary code",
			Type:      domain.TypeVulnerability,
			Severity:  domain.SevCritical,
			EffortMin: 20,
			Query:     `(call function: (identifier) @fn (#match? @fn "^(eval|exec)$")) @flag`,
			Capture:   "flag",
			Message:   "Avoid eval()/exec(); they execute arbitrary code. Use a safe parser (e.g. ast.literal_eval).",
		},
		{
			ID:        "py:todo-comment",
			Name:      "Track and resolve TODO/FIXME comments",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevInfo,
			EffortMin: 5,
			Query:     `((comment) @flag (#match? @flag "(TODO|FIXME|XXX)"))`,
			Capture:   "flag",
			Message:   "Complete the task described by this TODO/FIXME marker.",
		},
		{
			ID:        "py:bare-except",
			Name:      "Bare 'except:' hides errors",
			Type:      domain.TypeBug,
			Severity:  domain.SevMajor,
			EffortMin: 10,
			Query:     `(except_clause) @flag`,
			Capture:   "flag",
			// A bare `except:` has only its body block as a named child;
			// `except SomeError:` also has the exception type.
			Predicate: func(n *sitter.Node, src []byte) (string, bool) {
				if n.NamedChildCount() > 1 {
					return "", false
				}
				return "Catch a specific exception type instead of using a bare 'except:'.", true
			},
		},
		{
			ID:        "py:os-system",
			Name:      "os.system() execution is security-sensitive",
			Type:      domain.TypeHotspot,
			Severity:  domain.SevMajor,
			EffortMin: 10,
			Query:     `(call function: (attribute attribute: (identifier) @m (#eq? @m "system"))) @flag`,
			Capture:   "flag",
			Message:   "Review this os.system() call: prefer subprocess with a list of args and no shell.",
		},
		{
			ID:        "py:yaml-unsafe-load",
			Name:      "yaml.load without SafeLoader can execute arbitrary objects",
			Type:      domain.TypeVulnerability,
			Severity:  domain.SevCritical,
			EffortMin: 15,
			Query:     `(call function: (attribute object: (identifier) @o attribute: (identifier) @m) (#eq? @o "yaml") (#eq? @m "load")) @flag`,
			Capture:   "flag",
			Message:   "Use yaml.safe_load (or Loader=SafeLoader); yaml.load can construct arbitrary objects.",
		},
		{
			ID:        "py:pickle-load",
			Name:      "Unpickling untrusted data executes arbitrary code",
			Type:      domain.TypeVulnerability,
			Severity:  domain.SevCritical,
			EffortMin: 20,
			Query:     `(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "pickle") (#match? @m "^(load|loads)$"))) @flag`,
			Capture:   "flag",
			Message:   "Avoid pickle on untrusted input; use a safe format (JSON) instead.",
		},
		{
			ID:        "py:debug-print",
			Name:      "Remove debug print() calls",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevInfo,
			EffortMin: 5,
			Query:     `(call function: (identifier) @fn (#eq? @fn "print")) @flag`,
			Capture:   "flag",
			Message:   "Remove this debug print(), or use the logging module.",
		},
		{
			ID:        "py:assert-tuple",
			Name:      "assert on a tuple is always true",
			Type:      domain.TypeBug,
			Severity:  domain.SevMajor,
			EffortMin: 5,
			Query:     `(assert_statement (tuple)) @flag`,
			Capture:   "flag",
			Message:   "assert (a, b) asserts a non-empty tuple (always true). Use `assert a, \"b\"`.",
		},
		{
			ID:        "py:mutable-default-arg",
			Name:      "Mutable default argument",
			Type:      domain.TypeBug,
			Severity:  domain.SevMajor,
			EffortMin: 10,
			Query:     `(default_parameter value: [(list) (dictionary) (set)]) @flag`,
			Capture:   "flag",
			Message:   "A mutable default ([], {}) is shared across calls; use None and create the value inside.",
		},
		{
			ID:        "py:wildcard-import",
			Name:      "Wildcard import pollutes the namespace",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMinor,
			EffortMin: 5,
			Query:     `(import_from_statement (wildcard_import)) @flag`,
			Capture:   "flag",
			Message:   "Avoid `from x import *`; import the names you use explicitly.",
		},
		{
			ID:        "py:subprocess-shell",
			Name:      "subprocess called with shell=True",
			Type:      domain.TypeHotspot,
			Severity:  domain.SevMajor,
			EffortMin: 15,
			Query:     `(call function: (attribute object: (identifier) @o attribute: (identifier) @m) arguments: (argument_list (keyword_argument name: (identifier) @kw value: (true))) (#eq? @o "subprocess") (#match? @m "^(call|run|Popen|check_output|check_call)$") (#eq? @kw "shell")) @flag`,
			Capture:   "flag",
			Message:   "shell=True runs the command through a shell; if any argument is attacker-controlled this is command injection. Pass an argument list and shell=False.",
		},
		{
			ID:        "py:weak-hash",
			Name:      "Weak cryptographic hash (MD5/SHA-1)",
			Type:      domain.TypeHotspot,
			Severity:  domain.SevMajor,
			EffortMin: 15,
			Query:     `(call function: (attribute object: (identifier) @o attribute: (identifier) @m) (#eq? @o "hashlib") (#match? @m "^(md5|sha1)$")) @flag`,
			Capture:   "flag",
			Message:   "MD5/SHA-1 are weak; use hashlib.sha256+ for security-sensitive hashing (and a KDF like bcrypt/argon2 for passwords).",
		},
		{
			ID:        "py:requests-no-verify",
			Name:      "TLS verification disabled (verify=False)",
			Type:      domain.TypeHotspot,
			Severity:  domain.SevCritical,
			EffortMin: 20,
			Query:     `(call function: (attribute object: (identifier) @o) arguments: (argument_list (keyword_argument name: (identifier) @kw value: (false))) (#eq? @o "requests") (#eq? @kw "verify")) @flag`,
			Capture:   "flag",
			Message:   "verify=False disables TLS certificate validation, enabling man-in-the-middle attacks. Use the default (verify=True) or pass a CA bundle path.",
		},
		{
			ID:        "py:hardcoded-credentials",
			Name:      "Hard-coded credentials",
			Type:      domain.TypeHotspot,
			Severity:  domain.SevCritical,
			EffortMin: 20,
			Query:     `(assignment left: (identifier) @n right: (string (string_content)) (#match? @n "(?i)(passwd|password|pwd|secret|apikey|api_key|access_key|private_key)")) @flag`,
			Capture:   "flag",
			Message:   "Credential assigned from a string literal; load secrets from the environment (os.environ) or a secrets manager.",
		},
		pythonTaintSQLRule(),
		pythonTaintExecRule(),
		complexityRule(langspec.Python()),
	}
}
