package rules

import (
	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/lang"
)

// Taxonomy is the extra metadata (descriptions + security mappings) attached to
// a rule for the rule catalogue, SARIF descriptors, and the dashboard. Kept in
// one place so rule definitions stay terse.
type Taxonomy struct {
	Description string   `json:"description,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	CWE         []string `json:"cwe,omitempty"`
	OWASP       []string `json:"owasp,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// remediation maps rule id -> "how to fix" guidance, shown in the rule
// catalogue and SARIF help. Kept separate to keep the taxonomy table readable.
var remediation = map[string]string{
	"py:exec-eval":        "Don't eval/exec untrusted input. Use ast.literal_eval for data, or dispatch on an explicit allow-list of operations.",
	"py:yaml-unsafe-load": "Use yaml.safe_load (or yaml.load(..., Loader=yaml.SafeLoader)).",
	"py:pickle-load":      "Never unpickle untrusted data. Use JSON or another safe, schema-checked format.",
	"py:os-system":        "Use subprocess.run([...], shell=False) with an argument list; never build a shell string from input.",
	"py:tainted-sql":      "Use parameterized queries: cursor.execute(\"... WHERE x = %s\", (value,)). Never concatenate input into SQL.",
	"py:bare-except":      "Catch the specific exception type(s) you expect; let unexpected ones propagate.",
	"go:exec-command":     "Pass a fixed binary and an argument slice (no shell); validate/allow-list any input-derived arguments.",
	"go:weak-hash":        "Use crypto/sha256 (or stronger). For passwords use bcrypt/argon2, not a raw hash.",
	"go:tainted-exec":     "Don't pass untrusted input as the command/args. Use a fixed binary + validated arg slice.",
	"go:tainted-sql":      "Use parameterized queries with placeholders ($1, ?) and pass values as args; never concatenate input.",
	"js:eval-usage":       "Remove eval(); parse JSON with JSON.parse or dispatch explicitly.",
	"js:tainted-eval":     "Never eval request data. Parse/validate it, or dispatch on an allow-list.",
	"ts:tainted-eval":     "Never eval request data. Parse/validate it, or dispatch on an allow-list.",

	"ts:eval-usage":      "Remove eval(); parse JSON with JSON.parse or dispatch explicitly.",
	"js:inner-html":      "Use textContent, or sanitize HTML with a vetted library (e.g. DOMPurify) before assignment.",
	"ts:inner-html":      "Use textContent, or sanitize HTML with a vetted library (e.g. DOMPurify) before assignment.",
	"js:document-write":  "Build DOM nodes or set textContent; if HTML is required, sanitize it first.",
	"ts:document-write":  "Build DOM nodes or set textContent; if HTML is required, sanitize it first.",
	"java:process-exec":  "Use ProcessBuilder with an argument list and no shell; validate any input-derived arguments.",
	"java:catch-generic": "Catch the narrowest exception types you can handle; rethrow or wrap the rest.",
}

// ruleTaxonomy maps rule id -> taxonomy. Security rules carry CWE/OWASP; others
// get a short description where useful. Unlisted rules fall back to their name.
var ruleTaxonomy = map[string]Taxonomy{
	// Python
	"py:exec-eval":        {Description: "eval()/exec() execute arbitrary code; an attacker who controls the argument gets code execution.", CWE: []string{"CWE-95"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "injection"}},
	"py:yaml-unsafe-load": {Description: "yaml.load without SafeLoader can instantiate arbitrary Python objects (deserialization RCE).", CWE: []string{"CWE-502"}, OWASP: []string{"A08:2021-Software and Data Integrity Failures"}, Tags: []string{"security", "deserialization"}},
	"py:pickle-load":      {Description: "Unpickling untrusted data can execute arbitrary code during object reconstruction.", CWE: []string{"CWE-502"}, OWASP: []string{"A08:2021-Software and Data Integrity Failures"}, Tags: []string{"security", "deserialization"}},
	"py:os-system":        {Description: "os.system runs a string through the shell; untrusted input enables command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
	"py:tainted-sql":      {Description: "Dataflow: untrusted input (input()/os.getenv/request) is concatenated into a SQL query passed to cursor.execute; use parameterized queries.", CWE: []string{"CWE-89"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "sql-injection", "taint"}},
	"py:bare-except":      {Description: "A bare except: catches everything (including KeyboardInterrupt/SystemExit) and hides real errors.", CWE: []string{"CWE-396"}, Tags: []string{"error-handling"}},

	// Go
	"go:exec-command": {Description: "Building OS commands from untrusted input can lead to command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
	"go:weak-hash":    {Description: "MD5 and SHA-1 are cryptographically broken for security use; prefer SHA-256 or stronger.", CWE: []string{"CWE-327", "CWE-328"}, OWASP: []string{"A02:2021-Cryptographic Failures"}, Tags: []string{"security", "cryptography"}},
	"go:panic-usage":  {Description: "panic() aborts the goroutine; return an error so callers can handle failure.", Tags: []string{"error-handling"}},
	"go:tainted-exec": {Description: "Dataflow: untrusted input (os.Getenv/os.Args/flag) reaches exec.Command without sanitization, enabling command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection", "taint"}},
	"go:tainted-sql":  {Description: "Dataflow: untrusted input is concatenated into a SQL query; use parameterized queries.", CWE: []string{"CWE-89"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "sql-injection", "taint"}},

	// JS / TS (both prefixes share semantics)
	"js:eval-usage":         {Description: "eval() executes arbitrary code from a string.", CWE: []string{"CWE-95"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "injection"}},
	"ts:eval-usage":         {Description: "eval() executes arbitrary code from a string.", CWE: []string{"CWE-95"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "injection"}},
	"js:inner-html":         {Description: "Assigning untrusted data to innerHTML enables DOM-based XSS.", CWE: []string{"CWE-79"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "xss"}},
	"ts:inner-html":         {Description: "Assigning untrusted data to innerHTML enables DOM-based XSS.", CWE: []string{"CWE-79"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "xss"}},
	"js:child-process-exec": {Description: "child_process exec runs a shell; untrusted input enables command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
	"ts:child-process-exec": {Description: "child_process exec runs a shell; untrusted input enables command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
	"js:tainted-eval":       {Description: "Dataflow: request data (req.*/request.*) reaches eval(); arbitrary code execution.", CWE: []string{"CWE-95"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "injection", "taint"}},
	"ts:tainted-eval":       {Description: "Dataflow: request data (req.*/request.*) reaches eval(); arbitrary code execution.", CWE: []string{"CWE-95"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "injection", "taint"}},
	"js:tainted-xss":        {Description: "Dataflow: request data reaches innerHTML/outerHTML; DOM-based XSS.", CWE: []string{"CWE-79"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "xss", "taint"}},
	"js:tainted-exec":       {Description: "Dataflow: request data reaches a command-execution call (child_process); command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection", "taint"}},
	"ts:tainted-xss":        {Description: "Dataflow: request data reaches innerHTML/outerHTML; DOM-based XSS.", CWE: []string{"CWE-79"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "xss", "taint"}},
	"ts:tainted-exec":       {Description: "Dataflow: request data reaches a command-execution call (child_process); command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection", "taint"}},
	"js:loose-equality":     {Description: "== / != perform type coercion with surprising results; prefer === / !==.", Tags: []string{"pitfall"}},
	"ts:loose-equality":     {Description: "== / != perform type coercion with surprising results; prefer === / !==.", Tags: []string{"pitfall"}},
	"js:document-write":     {Description: "document.write with untrusted data enables DOM XSS (and blocks the parser).", CWE: []string{"CWE-79"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "xss"}},
	"ts:document-write":     {Description: "document.write with untrusted data enables DOM XSS (and blocks the parser).", CWE: []string{"CWE-79"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "xss"}},

	// Java
	"java:process-exec":  {Description: "Runtime/ProcessBuilder exec with untrusted input enables command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
	"java:catch-generic": {Description: "Catching Exception/Throwable hides specific failures and can swallow errors you should handle.", CWE: []string{"CWE-396"}, Tags: []string{"error-handling"}},
	"java:empty-catch":   {Description: "An empty catch block silently discards the exception.", CWE: []string{"CWE-390"}, Tags: []string{"error-handling"}},
}

// Meta is a catalogue entry describing one rule.
type Meta struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Language    string           `json:"language"`
	Type        domain.IssueType `json:"type"`
	Severity    domain.Severity  `json:"severity"`
	EffortMin   int              `json:"effortMin"`
	Description string           `json:"description,omitempty"`
	Remediation string           `json:"remediation,omitempty"`
	CWE         []string         `json:"cwe,omitempty"`
	OWASP       []string         `json:"owasp,omitempty"`
	Tags        []string         `json:"tags,omitempty"`
}

// TaxonomyFor returns the taxonomy for a rule id (merging remediation text).
func TaxonomyFor(id string) Taxonomy {
	t := ruleTaxonomy[id]
	if r, ok := remediation[id]; ok {
		t.Remediation = r
	}
	return t
}

// Catalog returns metadata for every built-in rule across all languages,
// merging in the security taxonomy.
func Catalog() []Meta {
	var out []Meta
	for _, l := range Languages() {
		for _, r := range ForLanguage(l) {
			t := TaxonomyFor(r.ID)
			desc := t.Description
			if desc == "" {
				desc = r.Name
			}
			out = append(out, Meta{
				ID: r.ID, Name: r.Name, Language: string(l), Type: r.Type,
				Severity: r.Severity, EffortMin: r.EffortMin,
				Description: desc, Remediation: t.Remediation,
				CWE: t.CWE, OWASP: t.OWASP, Tags: t.Tags,
			})
		}
	}
	return out
}

// CatalogFor returns the catalogue for a single language.
func CatalogFor(l lang.Language) []Meta {
	var out []Meta
	for _, m := range Catalog() {
		if m.Language == string(l) {
			out = append(out, m)
		}
	}
	return out
}
