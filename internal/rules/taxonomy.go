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
	"py:exec-eval":                "Don't eval/exec untrusted input. Use ast.literal_eval for data, or dispatch on an explicit allow-list of operations.",
	"py:yaml-unsafe-load":         "Use yaml.safe_load (or yaml.load(..., Loader=yaml.SafeLoader)).",
	"py:pickle-load":              "Never unpickle untrusted data. Use JSON or another safe, schema-checked format.",
	"py:os-system":                "Use subprocess.run([...], shell=False) with an argument list; never build a shell string from input.",
	"py:tainted-sql":              "Use parameterized queries: cursor.execute(\"... WHERE x = %s\", (value,)). Never concatenate input into SQL.",
	"py:tainted-exec":             "Avoid passing untrusted input to os.system/subprocess; use an argument list (shell=False) and validate input.",
	"py:bare-except":              "Catch the specific exception type(s) you expect; let unexpected ones propagate.",
	"py:subprocess-shell":         "Pass an argument list with shell=False; never build a shell string from input.",
	"py:weak-hash":                "Use hashlib.sha256 (or stronger). For passwords use bcrypt/argon2, not a raw hash.",
	"py:requests-no-verify":       "Leave verify at its default (True), or pass a CA bundle path; never disable verification in production.",
	"py:hardcoded-credentials":    "Read secrets from os.environ or a secrets manager — never commit them in source.",
	"go:exec-command":             "Pass a fixed binary and an argument slice (no shell); validate/allow-list any input-derived arguments.",
	"go:weak-hash":                "Use crypto/sha256 (or stronger). For passwords use bcrypt/argon2, not a raw hash.",
	"go:tainted-exec":             "Don't pass untrusted input as the command/args. Use a fixed binary + validated arg slice.",
	"go:tainted-sql":              "Use parameterized queries with placeholders ($1, ?) and pass values as args; never concatenate input.",
	"go:tls-insecure-skip-verify": "Remove InsecureSkipVerify (or set it false). For self-signed certs, add the CA to a custom RootCAs pool instead.",
	"go:discarded-append":         "Assign the result back: s = append(s, x). append() never mutates its argument in place.",
	"go:defer-in-loop":            "Move the loop body into a function so defer runs each iteration, or call the cleanup explicitly at the end of the body.",
	"js:eval-usage":               "Remove eval(); parse JSON with JSON.parse or dispatch explicitly.",
	"js:tainted-eval":             "Never eval request data. Parse/validate it, or dispatch on an allow-list.",
	"ts:tainted-eval":             "Never eval request data. Parse/validate it, or dispatch on an allow-list.",
	"js:tainted-sql":              "Use parameterized queries / prepared statements with placeholders; never build SQL from request data.",
	"ts:tainted-sql":              "Use parameterized queries / prepared statements with placeholders; never build SQL from request data.",

	"ts:eval-usage":              "Remove eval(); parse JSON with JSON.parse or dispatch explicitly.",
	"js:inner-html":              "Use textContent, or sanitize HTML with a vetted library (e.g. DOMPurify) before assignment.",
	"ts:inner-html":              "Use textContent, or sanitize HTML with a vetted library (e.g. DOMPurify) before assignment.",
	"js:document-write":          "Build DOM nodes or set textContent; if HTML is required, sanitize it first.",
	"ts:document-write":          "Build DOM nodes or set textContent; if HTML is required, sanitize it first.",
	"js:implied-eval":            "Pass a function reference: setTimeout(fn, ms). Never pass code as a string.",
	"ts:implied-eval":            "Pass a function reference: setTimeout(fn, ms). Never pass code as a string.",
	"js:empty-catch":             "Log the error, rethrow, or comment why it is safe to ignore.",
	"ts:empty-catch":             "Log the error, rethrow, or comment why it is safe to ignore.",
	"js:hardcoded-credentials":   "Read secrets from process.env or a secrets manager — never commit them in source.",
	"ts:hardcoded-credentials":   "Read secrets from process.env or a secrets manager — never commit them in source.",
	"java:process-exec":          "Use ProcessBuilder with an argument list and no shell; validate any input-derived arguments.",
	"java:catch-generic":         "Catch the narrowest exception types you can handle; rethrow or wrap the rest.",
	"java:string-eq-ref":         "Use a.equals(b) or Objects.equals(a, b); reserve == for reference identity.",
	"java:catch-npe":             "Remove the catch and fix the null dereference: validate inputs or use Optional.",
	"java:hardcoded-credentials": "Read secrets from environment variables, a vault, or config — never commit them in source.",
	"java:tainted-sql":           "Use a PreparedStatement with bind parameters (?), not string concatenation of request data.",
	"java:tainted-exec":          "Use ProcessBuilder with a validated argument list; never pass request data to Runtime.exec.",
	"php:eval-usage":             "Remove eval(); parse/validate input or dispatch on an explicit allow-list.",
	"php:exec-usage":             "Avoid shell exec with untrusted input; use escapeshellarg() or a non-shell API.",
	"php:weak-hash":              "Use hash('sha256', ...) (or stronger); use password_hash()/password_verify() for passwords.",
	"ruby:eval-usage":            "Remove eval/instance_eval on input; parse or dispatch on an allow-list.",
	"ruby:command-exec":          "Pass an argument array (system(cmd, *args)) and validate input; avoid backticks on untrusted data.",
	"ruby:weak-hash":             "Use Digest::SHA256 (or stronger); use bcrypt/argon2 for passwords.",
	"c:unsafe-cstring-fn":        "Use a bounded variant: snprintf, strncpy/strlcpy, fgets — and always size the destination.",
	"c:system-exec":              "Avoid system/popen with untrusted input; use exec* with an argument vector and validated input.",
	"cpp:unsafe-cstring-fn":      "Prefer std::string / std::format, or bounded C APIs (snprintf, strncpy).",
	"cpp:system-exec":            "Avoid system/popen with untrusted input; use a process API with an argument vector.",
	"cs:empty-catch":             "Log the exception, rethrow, or document why it is safe to ignore.",
	"cs:weak-hash":               "Use SHA256/SHA512; use PBKDF2/bcrypt/argon2 for passwords.",
	"cs:process-start":           "Use ProcessStartInfo with ArgumentList (no shell) and validate input-derived arguments.",
	"bash:eval-usage":            "Avoid eval; validate/whitelist input, or use arrays and quoting instead of building command strings.",
	"bash:curl-pipe-shell":       "Download to a file, verify a checksum/signature, then run it — do not pipe a URL into a shell.",
	"kt:not-null-assertion":      "Replace !! with a safe call (?.), Elvis (?:), or an explicit null check.",
	"kt:runtime-exec":            "Use ProcessBuilder with an argument list (no shell) and validate input-derived arguments.",
	"rust:unsafe-block":          "Minimize unsafe; encapsulate it behind a safe API and document the invariants that keep it sound.",
	"rust:panic-macro":           "Return a Result or handle the case; reserve panic!/unreachable! for genuinely impossible states.",
	"swift:force-unwrap":         "Use if let / guard let / nil-coalescing (??) instead of force-unwrapping.",
	"swift:force-try":            "Use do/try/catch or try? instead of try!.",
	"scala:null-usage":           "Model absence with Option (Some/None) instead of null.",
	"scala:asinstanceof":         "Use pattern matching (match/case) for checked casts instead of asInstanceOf.",
}

// ruleTaxonomy maps rule id -> taxonomy. Security rules carry CWE/OWASP; others
// get a short description where useful. Unlisted rules fall back to their name.
var ruleTaxonomy = map[string]Taxonomy{
	// Python
	"py:exec-eval":             {Description: "eval()/exec() execute arbitrary code; an attacker who controls the argument gets code execution.", CWE: []string{"CWE-95"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "injection"}},
	"py:yaml-unsafe-load":      {Description: "yaml.load without SafeLoader can instantiate arbitrary Python objects (deserialization RCE).", CWE: []string{"CWE-502"}, OWASP: []string{"A08:2021-Software and Data Integrity Failures"}, Tags: []string{"security", "deserialization"}},
	"py:pickle-load":           {Description: "Unpickling untrusted data can execute arbitrary code during object reconstruction.", CWE: []string{"CWE-502"}, OWASP: []string{"A08:2021-Software and Data Integrity Failures"}, Tags: []string{"security", "deserialization"}},
	"py:os-system":             {Description: "os.system runs a string through the shell; untrusted input enables command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
	"py:tainted-sql":           {Description: "Dataflow: untrusted input (input()/os.getenv/request) is concatenated into a SQL query passed to cursor.execute; use parameterized queries.", CWE: []string{"CWE-89"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "sql-injection", "taint"}},
	"py:tainted-exec":          {Description: "Dataflow: untrusted input (input()/os.getenv/request) reaches os.system/subprocess, enabling command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection", "taint"}},
	"py:bare-except":           {Description: "A bare except: catches everything (including KeyboardInterrupt/SystemExit) and hides real errors.", CWE: []string{"CWE-396"}, Tags: []string{"error-handling"}},
	"py:subprocess-shell":      {Description: "subprocess with shell=True runs a shell; untrusted arguments enable command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
	"py:weak-hash":             {Description: "MD5 and SHA-1 are cryptographically broken for security use; prefer SHA-256 or stronger.", CWE: []string{"CWE-327", "CWE-328"}, OWASP: []string{"A02:2021-Cryptographic Failures"}, Tags: []string{"security", "cryptography"}},
	"py:requests-no-verify":    {Description: "verify=False disables TLS certificate validation, exposing requests to man-in-the-middle attacks.", CWE: []string{"CWE-295"}, OWASP: []string{"A02:2021-Cryptographic Failures"}, Tags: []string{"security", "tls"}},
	"py:hardcoded-credentials": {Description: "Credentials embedded in source are exposed to anyone with repo access and cannot be rotated easily.", CWE: []string{"CWE-798"}, OWASP: []string{"A07:2021-Identification and Authentication Failures"}, Tags: []string{"security", "secrets"}},

	// Go
	"go:exec-command":             {Description: "Building OS commands from untrusted input can lead to command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
	"go:weak-hash":                {Description: "MD5 and SHA-1 are cryptographically broken for security use; prefer SHA-256 or stronger.", CWE: []string{"CWE-327", "CWE-328"}, OWASP: []string{"A02:2021-Cryptographic Failures"}, Tags: []string{"security", "cryptography"}},
	"go:panic-usage":              {Description: "panic() aborts the goroutine; return an error so callers can handle failure.", Tags: []string{"error-handling"}},
	"go:tainted-exec":             {Description: "Dataflow: untrusted input (os.Getenv/os.Args/flag) reaches exec.Command without sanitization, enabling command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection", "taint"}},
	"go:tainted-sql":              {Description: "Dataflow: untrusted input is concatenated into a SQL query; use parameterized queries.", CWE: []string{"CWE-89"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "sql-injection", "taint"}},
	"go:tls-insecure-skip-verify": {Description: "InsecureSkipVerify disables TLS certificate validation, exposing connections to man-in-the-middle attacks.", CWE: []string{"CWE-295"}, OWASP: []string{"A02:2021-Cryptographic Failures"}, Tags: []string{"security", "tls"}},
	"go:discarded-append":         {Description: "append() returns a new slice header; discarding it loses the appended elements.", CWE: []string{"CWE-1164"}, Tags: []string{"bug", "pitfall"}},
	"go:defer-in-loop":            {Description: "defer in a loop defers cleanup to function return, leaking resources (file handles, locks) across iterations.", CWE: []string{"CWE-404"}, Tags: []string{"bug", "resource-leak"}},

	// JS / TS (both prefixes share semantics)
	"js:eval-usage":            {Description: "eval() executes arbitrary code from a string.", CWE: []string{"CWE-95"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "injection"}},
	"ts:eval-usage":            {Description: "eval() executes arbitrary code from a string.", CWE: []string{"CWE-95"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "injection"}},
	"js:inner-html":            {Description: "Assigning untrusted data to innerHTML enables DOM-based XSS.", CWE: []string{"CWE-79"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "xss"}},
	"ts:inner-html":            {Description: "Assigning untrusted data to innerHTML enables DOM-based XSS.", CWE: []string{"CWE-79"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "xss"}},
	"js:child-process-exec":    {Description: "child_process exec runs a shell; untrusted input enables command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
	"ts:child-process-exec":    {Description: "child_process exec runs a shell; untrusted input enables command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
	"js:tainted-eval":          {Description: "Dataflow: request data (req.*/request.*) reaches eval(); arbitrary code execution.", CWE: []string{"CWE-95"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "injection", "taint"}},
	"ts:tainted-eval":          {Description: "Dataflow: request data (req.*/request.*) reaches eval(); arbitrary code execution.", CWE: []string{"CWE-95"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "injection", "taint"}},
	"js:tainted-xss":           {Description: "Dataflow: request data reaches innerHTML/outerHTML; DOM-based XSS.", CWE: []string{"CWE-79"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "xss", "taint"}},
	"js:tainted-exec":          {Description: "Dataflow: request data reaches a command-execution call (child_process); command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection", "taint"}},
	"ts:tainted-xss":           {Description: "Dataflow: request data reaches innerHTML/outerHTML; DOM-based XSS.", CWE: []string{"CWE-79"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "xss", "taint"}},
	"js:tainted-sql":           {Description: "Dataflow: request data reaches a SQL query (db.query/execute); SQL injection.", CWE: []string{"CWE-89"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "sql-injection", "taint"}},
	"ts:tainted-sql":           {Description: "Dataflow: request data reaches a SQL query (db.query/execute); SQL injection.", CWE: []string{"CWE-89"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "sql-injection", "taint"}},
	"ts:tainted-exec":          {Description: "Dataflow: request data reaches a command-execution call (child_process); command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection", "taint"}},
	"js:loose-equality":        {Description: "== / != perform type coercion with surprising results; prefer === / !==.", Tags: []string{"pitfall"}},
	"ts:loose-equality":        {Description: "== / != perform type coercion with surprising results; prefer === / !==.", Tags: []string{"pitfall"}},
	"js:document-write":        {Description: "document.write with untrusted data enables DOM XSS (and blocks the parser).", CWE: []string{"CWE-79"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "xss"}},
	"ts:document-write":        {Description: "document.write with untrusted data enables DOM XSS (and blocks the parser).", CWE: []string{"CWE-79"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "xss"}},
	"js:implied-eval":          {Description: "A string passed to setTimeout/setInterval is executed via eval, allowing code injection.", CWE: []string{"CWE-95"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "injection"}},
	"ts:implied-eval":          {Description: "A string passed to setTimeout/setInterval is executed via eval, allowing code injection.", CWE: []string{"CWE-95"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "injection"}},
	"js:empty-catch":           {Description: "An empty catch block silently discards the error.", CWE: []string{"CWE-390"}, Tags: []string{"error-handling"}},
	"ts:empty-catch":           {Description: "An empty catch block silently discards the error.", CWE: []string{"CWE-390"}, Tags: []string{"error-handling"}},
	"js:hardcoded-credentials": {Description: "Credentials embedded in source are exposed to anyone with repo access and cannot be rotated easily.", CWE: []string{"CWE-798"}, OWASP: []string{"A07:2021-Identification and Authentication Failures"}, Tags: []string{"security", "secrets"}},
	"ts:hardcoded-credentials": {Description: "Credentials embedded in source are exposed to anyone with repo access and cannot be rotated easily.", CWE: []string{"CWE-798"}, OWASP: []string{"A07:2021-Identification and Authentication Failures"}, Tags: []string{"security", "secrets"}},

	// Java
	"java:process-exec":          {Description: "Runtime/ProcessBuilder exec with untrusted input enables command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
	"java:catch-generic":         {Description: "Catching Exception/Throwable hides specific failures and can swallow errors you should handle.", CWE: []string{"CWE-396"}, Tags: []string{"error-handling"}},
	"java:empty-catch":           {Description: "An empty catch block silently discards the exception.", CWE: []string{"CWE-390"}, Tags: []string{"error-handling"}},
	"java:string-eq-ref":         {Description: "Comparing strings with ==/!= tests reference identity, not value, and fails for equal-but-distinct String objects.", CWE: []string{"CWE-597"}, Tags: []string{"bug", "pitfall"}},
	"java:catch-npe":             {Description: "Catching NullPointerException masks a programming error that should be fixed at the source.", CWE: []string{"CWE-395"}, Tags: []string{"error-handling"}},
	"java:hardcoded-credentials": {Description: "Credentials embedded in source are exposed to anyone with repo access and cannot be rotated easily.", CWE: []string{"CWE-798"}, OWASP: []string{"A07:2021-Identification and Authentication Failures"}, Tags: []string{"security", "secrets"}},
	"java:tainted-sql":           {Description: "Dataflow: untrusted request data (getParameter/getHeader/...) is concatenated into a JDBC execute call; SQL injection.", CWE: []string{"CWE-89"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "sql-injection", "taint"}},
	"java:tainted-exec":          {Description: "Dataflow: untrusted request data reaches Runtime.exec, enabling command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection", "taint"}},
	"php:eval-usage":             {Description: "eval() executes arbitrary PHP from a string.", CWE: []string{"CWE-95"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "injection"}},
	"php:exec-usage":             {Description: "system/exec/shell_exec/passthru run a shell; untrusted input enables command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
	"php:weak-hash":              {Description: "MD5 and SHA-1 are cryptographically broken for security use; prefer SHA-256 or stronger.", CWE: []string{"CWE-327", "CWE-328"}, OWASP: []string{"A02:2021-Cryptographic Failures"}, Tags: []string{"security", "cryptography"}},
	"ruby:eval-usage":            {Description: "eval/instance_eval execute arbitrary Ruby from a string.", CWE: []string{"CWE-95"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "injection"}},
	"ruby:command-exec":          {Description: "system/exec/spawn and backticks run a shell; untrusted input enables command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
	"ruby:weak-hash":             {Description: "MD5 and SHA-1 are cryptographically broken for security use; prefer SHA-256 or stronger.", CWE: []string{"CWE-327", "CWE-328"}, OWASP: []string{"A02:2021-Cryptographic Failures"}, Tags: []string{"security", "cryptography"}},
	"c:unsafe-cstring-fn":        {Description: "gets/strcpy/strcat/sprintf write without bounds; a long input overflows the buffer.", CWE: []string{"CWE-120", "CWE-242"}, Tags: []string{"security", "buffer-overflow"}},
	"c:system-exec":              {Description: "system/popen run a shell; untrusted input enables command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
	"cpp:unsafe-cstring-fn":      {Description: "gets/strcpy/strcat/sprintf write without bounds; a long input overflows the buffer.", CWE: []string{"CWE-120", "CWE-242"}, Tags: []string{"security", "buffer-overflow"}},
	"cpp:system-exec":            {Description: "system/popen run a shell; untrusted input enables command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
	"cs:empty-catch":             {Description: "An empty catch block silently discards the exception.", CWE: []string{"CWE-390"}, Tags: []string{"error-handling"}},
	"cs:weak-hash":               {Description: "MD5 and SHA-1 are cryptographically broken for security use; prefer SHA-256 or stronger.", CWE: []string{"CWE-327", "CWE-328"}, OWASP: []string{"A02:2021-Cryptographic Failures"}, Tags: []string{"security", "cryptography"}},
	"cs:process-start":           {Description: "Process.Start with untrusted input can lead to command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
	"bash:eval-usage":            {Description: "eval executes its argument as a shell command; untrusted input is command injection.", CWE: []string{"CWE-95"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "injection"}},
	"bash:curl-pipe-shell":       {Description: "Piping curl/wget output into a shell executes unverified remote code.", CWE: []string{"CWE-494"}, OWASP: []string{"A08:2021-Software and Data Integrity Failures"}, Tags: []string{"security", "supply-chain"}},
	"kt:not-null-assertion":      {Description: "The !! operator throws NullPointerException when the value is null, defeating Kotlin null safety.", CWE: []string{"CWE-476"}, Tags: []string{"pitfall", "null-safety"}},
	"kt:runtime-exec":            {Description: "Runtime.getRuntime().exec with untrusted input can lead to command injection.", CWE: []string{"CWE-78"}, OWASP: []string{"A03:2021-Injection"}, Tags: []string{"security", "command-injection"}},
	"rust:unsafe-block":          {Description: "unsafe disables the Rust memory-safety checks; misuse causes undefined behavior.", CWE: []string{"CWE-119"}, Tags: []string{"security", "memory"}},
	"rust:panic-macro":           {Description: "panic!/unreachable! abort the thread instead of returning a recoverable error.", Tags: []string{"error-handling"}},
	"swift:force-unwrap":         {Description: "Force-unwrapping a nil optional with ! crashes at runtime.", CWE: []string{"CWE-476"}, Tags: []string{"pitfall", "null-safety"}},
	"swift:force-try":            {Description: "try! crashes the process if the call throws, instead of handling the error.", Tags: []string{"error-handling"}},
	"scala:null-usage":           {Description: "Using null in Scala invites NullPointerExceptions; Option models absence safely.", CWE: []string{"CWE-476"}, Tags: []string{"pitfall", "null-safety"}},
	"scala:asinstanceof":         {Description: "asInstanceOf performs an unchecked cast that throws ClassCastException at runtime.", CWE: []string{"CWE-704"}, Tags: []string{"pitfall"}},
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
