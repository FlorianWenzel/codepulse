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
	CWE         []string `json:"cwe,omitempty"`
	OWASP       []string `json:"owasp,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// ruleTaxonomy maps rule id -> taxonomy. Security rules carry CWE/OWASP; others
// get a short description where useful. Unlisted rules fall back to their name.
var ruleTaxonomy = map[string]Taxonomy{
	// Python
	"py:exec-eval":        {Description: "eval()/exec() execute arbitrary code; an attacker who controls the argument gets code execution.", CWE: []string{"CWE-95"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "injection"}},
	"py:yaml-unsafe-load": {Description: "yaml.load without SafeLoader can instantiate arbitrary Python objects (deserialization RCE).", CWE: []string{"CWE-502"}, OWASP: []string{"A08:2021-Software and Data Integrity Failures"}, Tags: []string{"security", "deserialization"}},
	"py:pickle-load":      {Description: "Unpickling untrusted data can execute arbitrary code during object reconstruction.", CWE: []string{"CWE-502"}, OWASP: []string{"A08:2021-Software and Data Integrity Failures"}, Tags: []string{"security", "deserialization"}},
	"py:os-system":        {Description: "os.system runs a string through the shell; untrusted input enables command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
	"py:bare-except":      {Description: "A bare except: catches everything (including KeyboardInterrupt/SystemExit) and hides real errors.", CWE: []string{"CWE-396"}, Tags: []string{"error-handling"}},

	// Go
	"go:exec-command": {Description: "Building OS commands from untrusted input can lead to command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
	"go:weak-hash":    {Description: "MD5 and SHA-1 are cryptographically broken for security use; prefer SHA-256 or stronger.", CWE: []string{"CWE-327", "CWE-328"}, OWASP: []string{"A02:2021-Cryptographic Failures"}, Tags: []string{"security", "cryptography"}},
	"go:panic-usage":  {Description: "panic() aborts the goroutine; return an error so callers can handle failure.", Tags: []string{"error-handling"}},
	"go:tainted-exec": {Description: "Dataflow: a value from os.Getenv reaches exec.Command without sanitization, enabling command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection", "taint"}},

	// JS / TS (both prefixes share semantics)
	"js:eval-usage":         {Description: "eval() executes arbitrary code from a string.", CWE: []string{"CWE-95"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "injection"}},
	"ts:eval-usage":         {Description: "eval() executes arbitrary code from a string.", CWE: []string{"CWE-95"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "injection"}},
	"js:inner-html":         {Description: "Assigning untrusted data to innerHTML enables DOM-based XSS.", CWE: []string{"CWE-79"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "xss"}},
	"ts:inner-html":         {Description: "Assigning untrusted data to innerHTML enables DOM-based XSS.", CWE: []string{"CWE-79"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "xss"}},
	"js:child-process-exec": {Description: "child_process exec runs a shell; untrusted input enables command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
	"ts:child-process-exec": {Description: "child_process exec runs a shell; untrusted input enables command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
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
	CWE         []string         `json:"cwe,omitempty"`
	OWASP       []string         `json:"owasp,omitempty"`
	Tags        []string         `json:"tags,omitempty"`
}

// TaxonomyFor returns the taxonomy for a rule id (zero value if none).
func TaxonomyFor(id string) Taxonomy { return ruleTaxonomy[id] }

// Catalog returns metadata for every built-in rule across all languages,
// merging in the security taxonomy.
func Catalog() []Meta {
	var out []Meta
	for _, l := range Languages() {
		for _, r := range ForLanguage(l) {
			t := ruleTaxonomy[r.ID]
			desc := t.Description
			if desc == "" {
				desc = r.Name
			}
			out = append(out, Meta{
				ID: r.ID, Name: r.Name, Language: string(l), Type: r.Type,
				Severity: r.Severity, EffortMin: r.EffortMin,
				Description: desc, CWE: t.CWE, OWASP: t.OWASP, Tags: t.Tags,
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
