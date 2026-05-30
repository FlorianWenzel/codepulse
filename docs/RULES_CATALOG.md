# CodePulse Rule Catalogue

> Auto-generated from `codepulse-scan -rules`. Do not edit by hand —
> regenerate with `make rules-catalog`.

**170 built-in rules** across **15 languages** (plus secret detection & Dockerfile checks). Each rule carries a
type (BUG / VULNERABILITY / CODE_SMELL / SECURITY_HOTSPOT), a default severity,
a remediation hint, and — for security rules — CWE and OWASP Top 10 mappings.

## Summary

| Language | Rules |
|----------|------:|
| any | 8 |
| bash | 5 |
| c | 5 |
| cpp | 5 |
| csharp | 6 |
| docker | 5 |
| go | 17 |
| java | 19 |
| javascript | 24 |
| kotlin | 5 |
| php | 7 |
| python | 18 |
| ruby | 6 |
| rust | 6 |
| scala | 5 |
| swift | 5 |
| typescript | 24 |
| **Total** | **170** |

## any

| Rule ID | Name | Type | Severity | CWE | OWASP |
|---------|------|------|----------|-----|-------|
| `secret:aws-access-key-id` | AWS access key ID | VULNERABILITY | BLOCKER | CWE-798 | A07:2021-Identification and Authentication Failures |
| `secret:github-fine-grained-pat` | GitHub fine-grained PAT | VULNERABILITY | BLOCKER | CWE-798 | A07:2021-Identification and Authentication Failures |
| `secret:github-token` | GitHub token | VULNERABILITY | BLOCKER | CWE-798 | A07:2021-Identification and Authentication Failures |
| `secret:google-api-key` | Google API key | VULNERABILITY | BLOCKER | CWE-798 | A07:2021-Identification and Authentication Failures |
| `secret:private-key` | Private key block | VULNERABILITY | BLOCKER | CWE-798 | A07:2021-Identification and Authentication Failures |
| `secret:slack-token` | Slack token | VULNERABILITY | BLOCKER | CWE-798 | A07:2021-Identification and Authentication Failures |
| `secret:slack-webhook` | Slack webhook URL | VULNERABILITY | BLOCKER | CWE-798 | A07:2021-Identification and Authentication Failures |
| `secret:stripe-secret-key` | Stripe secret key | VULNERABILITY | BLOCKER | CWE-798 | A07:2021-Identification and Authentication Failures |

## bash

| Rule ID | Name | Type | Severity | CWE | OWASP |
|---------|------|------|----------|-----|-------|
| `bash:cognitive-complexity` | Function is hard to understand (cognitive complexity) | CODE_SMELL | MAJOR | — | — |
| `bash:curl-pipe-shell` | Piping a download straight into a shell | VULNERABILITY | CRITICAL | CWE-494 | A08:2021-Software and Data Integrity Failures |
| `bash:eval-usage` | Use of eval executes arbitrary commands | VULNERABILITY | CRITICAL | CWE-95 | A03:2021-Injection |
| `bash:high-complexity` | Function is too complex | CODE_SMELL | MAJOR | — | — |
| `bash:todo-comment` | Track and resolve TODO/FIXME comments | CODE_SMELL | INFO | — | — |

## c

| Rule ID | Name | Type | Severity | CWE | OWASP |
|---------|------|------|----------|-----|-------|
| `c:cognitive-complexity` | Function is hard to understand (cognitive complexity) | CODE_SMELL | MAJOR | — | — |
| `c:high-complexity` | Function is too complex | CODE_SMELL | MAJOR | — | — |
| `c:system-exec` | Shell command execution is security-sensitive | SECURITY_HOTSPOT | MAJOR | CWE-78 | A03:2021-Injection |
| `c:todo-comment` | Track and resolve TODO/FIXME comments | CODE_SMELL | INFO | — | — |
| `c:unsafe-cstring-fn` | Unsafe C string function (buffer overflow) | SECURITY_HOTSPOT | MAJOR | CWE-120, CWE-242 | — |

## cpp

| Rule ID | Name | Type | Severity | CWE | OWASP |
|---------|------|------|----------|-----|-------|
| `cpp:cognitive-complexity` | Function is hard to understand (cognitive complexity) | CODE_SMELL | MAJOR | — | — |
| `cpp:high-complexity` | Function is too complex | CODE_SMELL | MAJOR | — | — |
| `cpp:system-exec` | Shell command execution is security-sensitive | SECURITY_HOTSPOT | MAJOR | CWE-78 | A03:2021-Injection |
| `cpp:todo-comment` | Track and resolve TODO/FIXME comments | CODE_SMELL | INFO | — | — |
| `cpp:unsafe-cstring-fn` | Unsafe C string function (buffer overflow) | SECURITY_HOTSPOT | MAJOR | CWE-120, CWE-242 | — |

## csharp

| Rule ID | Name | Type | Severity | CWE | OWASP |
|---------|------|------|----------|-----|-------|
| `cs:cognitive-complexity` | Function is hard to understand (cognitive complexity) | CODE_SMELL | MAJOR | — | — |
| `cs:empty-catch` | Empty catch block swallows exceptions | BUG | MAJOR | CWE-390 | — |
| `cs:high-complexity` | Function is too complex | CODE_SMELL | MAJOR | — | — |
| `cs:process-start` | Process execution is security-sensitive | SECURITY_HOTSPOT | MAJOR | CWE-78 | A03:2021-Injection |
| `cs:todo-comment` | Track and resolve TODO/FIXME comments | CODE_SMELL | INFO | — | — |
| `cs:weak-hash` | Weak cryptographic hash (MD5/SHA-1) | SECURITY_HOTSPOT | MAJOR | CWE-327, CWE-328 | A02:2021-Cryptographic Failures |

## docker

| Rule ID | Name | Type | Severity | CWE | OWASP |
|---------|------|------|----------|-----|-------|
| `docker:add-local` | ADD used for local files | CODE_SMELL | MINOR | — | — |
| `docker:curl-pipe-shell` | Download piped into a shell in RUN | VULNERABILITY | CRITICAL | CWE-494 | — |
| `docker:from-latest` | Base image uses :latest | CODE_SMELL | MINOR | — | — |
| `docker:run-as-root` | Container runs as root (no USER) | SECURITY_HOTSPOT | MAJOR | CWE-250 | — |
| `docker:run-sudo` | sudo used in RUN | CODE_SMELL | MINOR | — | — |

## go

| Rule ID | Name | Type | Severity | CWE | OWASP |
|---------|------|------|----------|-----|-------|
| `go:cognitive-complexity` | Function is hard to understand (cognitive complexity) | CODE_SMELL | MAJOR | — | — |
| `go:context-todo` | context.TODO() should be replaced before release | CODE_SMELL | MINOR | — | — |
| `go:debug-print` | Remove debug print statements | CODE_SMELL | MINOR | — | — |
| `go:defer-in-loop` | defer inside a loop | BUG | MAJOR | CWE-404 | — |
| `go:discarded-append` | Result of append() is discarded | BUG | MAJOR | CWE-1164 | — |
| `go:empty-block` | Empty blocks should be removed or documented | CODE_SMELL | MINOR | — | — |
| `go:error-new-fmt` | Use fmt.Errorf instead of errors.New(fmt.Sprintf(...)) | CODE_SMELL | MINOR | — | — |
| `go:exec-command` | OS command execution is security-sensitive | SECURITY_HOTSPOT | MAJOR | CWE-78 | A03:2021-Injection |
| `go:high-complexity` | Function is too complex | CODE_SMELL | MAJOR | — | — |
| `go:ioutil-deprecated` | io/ioutil is deprecated (since Go 1.16) | CODE_SMELL | MINOR | — | — |
| `go:os-exit` | os.Exit() should not be used in library code | CODE_SMELL | MAJOR | — | — |
| `go:panic-usage` | panic() should not be used for normal control flow | CODE_SMELL | MAJOR | — | — |
| `go:tainted-exec` | Untrusted input flows into command execution | VULNERABILITY | CRITICAL | CWE-78 | A03:2021-Injection |
| `go:tainted-sql` | Untrusted input concatenated into a SQL query | VULNERABILITY | CRITICAL | CWE-89 | A03:2021-Injection |
| `go:tls-insecure-skip-verify` | TLS certificate verification disabled (InsecureSkipVerify) | SECURITY_HOTSPOT | CRITICAL | CWE-295 | A02:2021-Cryptographic Failures |
| `go:todo-comment` | Track and resolve TODO/FIXME comments | CODE_SMELL | INFO | — | — |
| `go:weak-hash` | Weak cryptographic hash (MD5/SHA-1) | SECURITY_HOTSPOT | MAJOR | CWE-327, CWE-328 | A02:2021-Cryptographic Failures |

## java

| Rule ID | Name | Type | Severity | CWE | OWASP |
|---------|------|------|----------|-----|-------|
| `java:assert-usage` | assert is disabled at runtime by default | CODE_SMELL | MINOR | — | — |
| `java:catch-generic` | Catch specific exceptions, not Exception/Throwable | CODE_SMELL | MAJOR | CWE-396 | — |
| `java:catch-npe` | NullPointerException should not be caught | CODE_SMELL | MAJOR | CWE-395 | — |
| `java:cognitive-complexity` | Function is hard to understand (cognitive complexity) | CODE_SMELL | MAJOR | — | — |
| `java:empty-catch` | Empty catch block swallows exceptions | BUG | MAJOR | CWE-390 | — |
| `java:hardcoded-credentials` | Hard-coded credentials | SECURITY_HOTSPOT | CRITICAL | CWE-798 | A07:2021-Identification and Authentication Failures |
| `java:high-complexity` | Function is too complex | CODE_SMELL | MAJOR | — | — |
| `java:legacy-collection` | Legacy synchronized collection | CODE_SMELL | MINOR | — | — |
| `java:print-stacktrace` | Don't expose stack traces via printStackTrace() | CODE_SMELL | MINOR | — | — |
| `java:process-exec` | Process execution is security-sensitive | SECURITY_HOTSPOT | MAJOR | CWE-78 | A03:2021-Injection |
| `java:string-eq-ref` | Strings compared with == instead of equals() | BUG | MAJOR | CWE-597 | — |
| `java:system-exit` | System.exit() should not be used in library code | CODE_SMELL | MAJOR | — | — |
| `java:system-print` | Remove System.out/err debug prints | CODE_SMELL | MINOR | — | — |
| `java:tainted-exec` | Untrusted request data flows into command execution | VULNERABILITY | CRITICAL | CWE-78 | A03:2021-Injection |
| `java:tainted-sql` | Untrusted request data concatenated into a SQL query | VULNERABILITY | CRITICAL | CWE-89 | A03:2021-Injection |
| `java:thread-sleep` | Thread.sleep() in application code is a smell | CODE_SMELL | MINOR | — | — |
| `java:todo-comment` | Track and resolve TODO/FIXME comments | CODE_SMELL | INFO | — | — |
| `java:unsafe-deserialization` | Deserialization of untrusted data | SECURITY_HOTSPOT | CRITICAL | CWE-502 | A08:2021-Software and Data Integrity Failures |
| `java:weak-hash` | Weak cryptographic hash (MD5/SHA-1) | SECURITY_HOTSPOT | MAJOR | CWE-327, CWE-328 | A02:2021-Cryptographic Failures |

## javascript

| Rule ID | Name | Type | Severity | CWE | OWASP |
|---------|------|------|----------|-----|-------|
| `js:alert` | Leftover alert()/confirm()/prompt() | CODE_SMELL | MINOR | — | — |
| `js:child-process-exec` | Command execution is security-sensitive | SECURITY_HOTSPOT | MAJOR | CWE-78 | A03:2021-Injection |
| `js:cognitive-complexity` | Function is hard to understand (cognitive complexity) | CODE_SMELL | MAJOR | — | — |
| `js:console-usage` | Remove console statements | CODE_SMELL | MINOR | — | — |
| `js:debugger-statement` | Leftover debugger statement | CODE_SMELL | MAJOR | — | — |
| `js:document-write` | document.write enables XSS and blocks parsing | SECURITY_HOTSPOT | MAJOR | CWE-79 | A03:2021-Injection |
| `js:empty-catch` | Empty catch block swallows errors | BUG | MAJOR | CWE-390 | — |
| `js:eval-usage` | Use of eval() executes arbitrary code | VULNERABILITY | CRITICAL | CWE-95 | A03:2021-Injection |
| `js:hardcoded-credentials` | Hard-coded credentials | SECURITY_HOTSPOT | CRITICAL | CWE-798 | A07:2021-Identification and Authentication Failures |
| `js:high-complexity` | Function is too complex | CODE_SMELL | MAJOR | — | — |
| `js:implied-eval` | setTimeout/setInterval called with a string | VULNERABILITY | CRITICAL | CWE-95 | A03:2021-Injection |
| `js:inner-html` | Assigning to innerHTML can introduce XSS | SECURITY_HOTSPOT | MAJOR | CWE-79 | A03:2021-Injection |
| `js:loose-equality` | Use strict equality (=== / !==) | CODE_SMELL | MINOR | — | — |
| `js:no-new-wrappers` | Don't use primitive wrapper constructors | CODE_SMELL | MINOR | — | — |
| `js:no-with` | Avoid the with statement | CODE_SMELL | MAJOR | — | — |
| `js:tainted-eval` | Request data flows into eval() | VULNERABILITY | CRITICAL | CWE-95 | A03:2021-Injection |
| `js:tainted-exec` | Request data flows into command execution | VULNERABILITY | CRITICAL | CWE-78 | A03:2021-Injection |
| `js:tainted-sql` | Request data flows into a SQL query | VULNERABILITY | CRITICAL | CWE-89 | A03:2021-Injection |
| `js:tainted-ssrf` | Request data flows into an outbound HTTP request | SECURITY_HOTSPOT | MAJOR | CWE-918 | A10:2021-Server-Side Request Forgery |
| `js:tainted-xss` | Request data assigned to innerHTML | VULNERABILITY | CRITICAL | CWE-79 | A03:2021-Injection |
| `js:throw-literal` | Throw an Error, not a literal | CODE_SMELL | MINOR | — | — |
| `js:todo-comment` | Track and resolve TODO/FIXME comments | CODE_SMELL | INFO | — | — |
| `js:var-declaration` | Prefer let/const over var | CODE_SMELL | MINOR | — | — |
| `js:weak-hash` | Weak cryptographic hash (MD5/SHA-1) | SECURITY_HOTSPOT | MAJOR | CWE-327, CWE-328 | A02:2021-Cryptographic Failures |

## kotlin

| Rule ID | Name | Type | Severity | CWE | OWASP |
|---------|------|------|----------|-----|-------|
| `kt:cognitive-complexity` | Function is hard to understand (cognitive complexity) | CODE_SMELL | MAJOR | — | — |
| `kt:high-complexity` | Function is too complex | CODE_SMELL | MAJOR | — | — |
| `kt:not-null-assertion` | Avoid the !! not-null assertion | CODE_SMELL | MAJOR | CWE-476 | — |
| `kt:runtime-exec` | Runtime command execution is security-sensitive | SECURITY_HOTSPOT | MAJOR | CWE-78 | A03:2021-Injection |
| `kt:todo-comment` | Track and resolve TODO/FIXME comments | CODE_SMELL | INFO | — | — |

## php

| Rule ID | Name | Type | Severity | CWE | OWASP |
|---------|------|------|----------|-----|-------|
| `php:cognitive-complexity` | Function is hard to understand (cognitive complexity) | CODE_SMELL | MAJOR | — | — |
| `php:eval-usage` | Use of eval() executes arbitrary code | VULNERABILITY | CRITICAL | CWE-95 | A03:2021-Injection |
| `php:exec-usage` | Shell command execution is security-sensitive | VULNERABILITY | CRITICAL | CWE-78 | A03:2021-Injection |
| `php:high-complexity` | Function is too complex | CODE_SMELL | MAJOR | — | — |
| `php:todo-comment` | Track and resolve TODO/FIXME comments | CODE_SMELL | INFO | — | — |
| `php:unsafe-deserialization` | Deserialization of untrusted data (unserialize) | SECURITY_HOTSPOT | CRITICAL | CWE-502 | A08:2021-Software and Data Integrity Failures |
| `php:weak-hash` | Weak cryptographic hash (MD5/SHA-1) | SECURITY_HOTSPOT | MAJOR | CWE-327, CWE-328 | A02:2021-Cryptographic Failures |

## python

| Rule ID | Name | Type | Severity | CWE | OWASP |
|---------|------|------|----------|-----|-------|
| `py:assert-tuple` | assert on a tuple is always true | BUG | MAJOR | — | — |
| `py:bare-except` | Bare 'except:' hides errors | BUG | MAJOR | CWE-396 | — |
| `py:cognitive-complexity` | Function is hard to understand (cognitive complexity) | CODE_SMELL | MAJOR | — | — |
| `py:debug-print` | Remove debug print() calls | CODE_SMELL | INFO | — | — |
| `py:exec-eval` | Use of eval()/exec() executes arbitrary code | VULNERABILITY | CRITICAL | CWE-95 | A03:2021-Injection |
| `py:hardcoded-credentials` | Hard-coded credentials | SECURITY_HOTSPOT | CRITICAL | CWE-798 | A07:2021-Identification and Authentication Failures |
| `py:high-complexity` | Function is too complex | CODE_SMELL | MAJOR | — | — |
| `py:mutable-default-arg` | Mutable default argument | BUG | MAJOR | — | — |
| `py:os-system` | os.system() execution is security-sensitive | SECURITY_HOTSPOT | MAJOR | CWE-78 | A03:2021-Injection |
| `py:pickle-load` | Unpickling untrusted data executes arbitrary code | VULNERABILITY | CRITICAL | CWE-502 | A08:2021-Software and Data Integrity Failures |
| `py:requests-no-verify` | TLS verification disabled (verify=False) | SECURITY_HOTSPOT | CRITICAL | CWE-295 | A02:2021-Cryptographic Failures |
| `py:subprocess-shell` | subprocess called with shell=True | SECURITY_HOTSPOT | MAJOR | CWE-78 | A03:2021-Injection |
| `py:tainted-exec` | Untrusted input flows into command execution | VULNERABILITY | CRITICAL | CWE-78 | A03:2021-Injection |
| `py:tainted-sql` | Untrusted input concatenated into a SQL query | VULNERABILITY | CRITICAL | CWE-89 | A03:2021-Injection |
| `py:todo-comment` | Track and resolve TODO/FIXME comments | CODE_SMELL | INFO | — | — |
| `py:weak-hash` | Weak cryptographic hash (MD5/SHA-1) | SECURITY_HOTSPOT | MAJOR | CWE-327, CWE-328 | A02:2021-Cryptographic Failures |
| `py:wildcard-import` | Wildcard import pollutes the namespace | CODE_SMELL | MINOR | — | — |
| `py:yaml-unsafe-load` | yaml.load without SafeLoader can execute arbitrary objects | VULNERABILITY | CRITICAL | CWE-502 | A08:2021-Software and Data Integrity Failures |

## ruby

| Rule ID | Name | Type | Severity | CWE | OWASP |
|---------|------|------|----------|-----|-------|
| `ruby:cognitive-complexity` | Function is hard to understand (cognitive complexity) | CODE_SMELL | MAJOR | — | — |
| `ruby:command-exec` | Shell command execution is security-sensitive | VULNERABILITY | CRITICAL | CWE-78 | A03:2021-Injection |
| `ruby:eval-usage` | Use of eval executes arbitrary code | VULNERABILITY | CRITICAL | CWE-95 | A03:2021-Injection |
| `ruby:high-complexity` | Function is too complex | CODE_SMELL | MAJOR | — | — |
| `ruby:todo-comment` | Track and resolve TODO/FIXME comments | CODE_SMELL | INFO | — | — |
| `ruby:weak-hash` | Weak cryptographic hash (MD5/SHA-1) | SECURITY_HOTSPOT | MAJOR | CWE-327, CWE-328 | A02:2021-Cryptographic Failures |

## rust

| Rule ID | Name | Type | Severity | CWE | OWASP |
|---------|------|------|----------|-----|-------|
| `rust:cognitive-complexity` | Function is hard to understand (cognitive complexity) | CODE_SMELL | MAJOR | — | — |
| `rust:high-complexity` | Function is too complex | CODE_SMELL | MAJOR | — | — |
| `rust:panic-macro` | panic!/unreachable! aborts instead of returning an error | CODE_SMELL | MAJOR | — | — |
| `rust:todo-comment` | Track and resolve TODO/FIXME comments | CODE_SMELL | INFO | — | — |
| `rust:unsafe-block` | unsafe block bypasses Rust's safety guarantees | SECURITY_HOTSPOT | MAJOR | CWE-119 | — |
| `rust:unwrap` | Avoid .unwrap(); handle the error or None case | CODE_SMELL | MINOR | — | — |

## scala

| Rule ID | Name | Type | Severity | CWE | OWASP |
|---------|------|------|----------|-----|-------|
| `scala:asinstanceof` | Unsafe cast with asInstanceOf | CODE_SMELL | MAJOR | CWE-704 | — |
| `scala:cognitive-complexity` | Function is hard to understand (cognitive complexity) | CODE_SMELL | MAJOR | — | — |
| `scala:high-complexity` | Function is too complex | CODE_SMELL | MAJOR | — | — |
| `scala:null-usage` | Avoid null; use Option | CODE_SMELL | MAJOR | CWE-476 | — |
| `scala:todo-comment` | Track and resolve TODO/FIXME comments | CODE_SMELL | INFO | — | — |

## swift

| Rule ID | Name | Type | Severity | CWE | OWASP |
|---------|------|------|----------|-----|-------|
| `swift:cognitive-complexity` | Function is hard to understand (cognitive complexity) | CODE_SMELL | MAJOR | — | — |
| `swift:force-try` | Avoid force-try (try!) | CODE_SMELL | MAJOR | — | — |
| `swift:force-unwrap` | Avoid force-unwrapping optionals (!) | CODE_SMELL | MAJOR | CWE-476 | — |
| `swift:high-complexity` | Function is too complex | CODE_SMELL | MAJOR | — | — |
| `swift:todo-comment` | Track and resolve TODO/FIXME comments | CODE_SMELL | INFO | — | — |

## typescript

| Rule ID | Name | Type | Severity | CWE | OWASP |
|---------|------|------|----------|-----|-------|
| `ts:alert` | Leftover alert()/confirm()/prompt() | CODE_SMELL | MINOR | — | — |
| `ts:child-process-exec` | Command execution is security-sensitive | SECURITY_HOTSPOT | MAJOR | CWE-78 | A03:2021-Injection |
| `ts:cognitive-complexity` | Function is hard to understand (cognitive complexity) | CODE_SMELL | MAJOR | — | — |
| `ts:console-usage` | Remove console statements | CODE_SMELL | MINOR | — | — |
| `ts:debugger-statement` | Leftover debugger statement | CODE_SMELL | MAJOR | — | — |
| `ts:document-write` | document.write enables XSS and blocks parsing | SECURITY_HOTSPOT | MAJOR | CWE-79 | A03:2021-Injection |
| `ts:empty-catch` | Empty catch block swallows errors | BUG | MAJOR | CWE-390 | — |
| `ts:eval-usage` | Use of eval() executes arbitrary code | VULNERABILITY | CRITICAL | CWE-95 | A03:2021-Injection |
| `ts:hardcoded-credentials` | Hard-coded credentials | SECURITY_HOTSPOT | CRITICAL | CWE-798 | A07:2021-Identification and Authentication Failures |
| `ts:high-complexity` | Function is too complex | CODE_SMELL | MAJOR | — | — |
| `ts:implied-eval` | setTimeout/setInterval called with a string | VULNERABILITY | CRITICAL | CWE-95 | A03:2021-Injection |
| `ts:inner-html` | Assigning to innerHTML can introduce XSS | SECURITY_HOTSPOT | MAJOR | CWE-79 | A03:2021-Injection |
| `ts:loose-equality` | Use strict equality (=== / !==) | CODE_SMELL | MINOR | — | — |
| `ts:no-new-wrappers` | Don't use primitive wrapper constructors | CODE_SMELL | MINOR | — | — |
| `ts:no-with` | Avoid the with statement | CODE_SMELL | MAJOR | — | — |
| `ts:tainted-eval` | Request data flows into eval() | VULNERABILITY | CRITICAL | CWE-95 | A03:2021-Injection |
| `ts:tainted-exec` | Request data flows into command execution | VULNERABILITY | CRITICAL | CWE-78 | A03:2021-Injection |
| `ts:tainted-sql` | Request data flows into a SQL query | VULNERABILITY | CRITICAL | CWE-89 | A03:2021-Injection |
| `ts:tainted-ssrf` | Request data flows into an outbound HTTP request | SECURITY_HOTSPOT | MAJOR | CWE-918 | A10:2021-Server-Side Request Forgery |
| `ts:tainted-xss` | Request data assigned to innerHTML | VULNERABILITY | CRITICAL | CWE-79 | A03:2021-Injection |
| `ts:throw-literal` | Throw an Error, not a literal | CODE_SMELL | MINOR | — | — |
| `ts:todo-comment` | Track and resolve TODO/FIXME comments | CODE_SMELL | INFO | — | — |
| `ts:var-declaration` | Prefer let/const over var | CODE_SMELL | MINOR | — | — |
| `ts:weak-hash` | Weak cryptographic hash (MD5/SHA-1) | SECURITY_HOTSPOT | MAJOR | CWE-327, CWE-328 | A02:2021-Cryptographic Failures |

