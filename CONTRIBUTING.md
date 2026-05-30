# Contributing to CodePulse

Thanks for your interest! This guide documents how the project is **actually**
built today, so you can add value quickly. (The forward-looking YAML rule
format in [docs/RULES.md](docs/RULES.md) §3 is a planned authoring layer; rules
today are small Go values — see below.)

## Prerequisites

- Go 1.23+ (the scanner uses CGo tree-sitter bindings, so a C toolchain is needed).
- Node 18+ for the dashboard (`web/`).

```sh
make build     # builds bin/codepulse-scan and bin/codepulse-server
make test      # full Go suite (unit + e2e, incl. an embedded Postgres)
make vet       # go vet ./...
cd web && npm install && npm test   # dashboard (Vitest)
```

## Repo layout

- `internal/scan/` — scan orchestration (walk → parse → metrics → rules → dedup → ratings).
- `internal/langspec/` — per-language node-kind maps that make metrics/rules language-agnostic.
- `internal/rules/` — the rule engine (`engine.go`), registry (`registry.go`), per-language
  rule sets (`builtin_*.go`), the metadata taxonomy (`taxonomy.go`), and the taint engines
  (`taint_*.go`).
- `internal/server/` — HTTP API, store (in-memory + Postgres), quality gates, OIDC, GitHub decoration.
- `web/` — Vue 3 dashboard.
- `testdata/` — fixtures each rule is tested against.

## Adding a rule (the real workflow)

A rule is a `rules.Rule` value (see `internal/rules/engine.go`). Three kinds:

1. **Query rule** — a tree-sitter query plus a capture:
   ```go
   {
       ID: "go:weak-hash", Name: "Weak cryptographic hash (MD5/SHA-1)",
       Type: domain.TypeHotspot, Severity: domain.SevMajor, EffortMin: 15,
       Query: `(call_expression function: (selector_expression operand: (identifier) @pkg field: (field_identifier) @fn) (#match? @pkg "^(md5|sha1)$") (#eq? @fn "New")) @flag`,
       Capture: "flag",
       Message: "MD5/SHA-1 are weak; use SHA-256+ for security-sensitive hashing.",
   }
   ```
2. **Query + predicate** — when the match needs a condition the query can't express; set
   `Predicate func(n, src) (msg string, keep bool)` (e.g. empty-block, threshold checks).
3. **Visitor rule** — set `Visit func(root, src, emit)` for anything needing tree walking or
   intra-procedural dataflow (see `taint_*.go`, `registry.go` complexity rules).

Steps:

1. Add the rule to the language's set in `internal/rules/builtin_<lang>.go` (or `taint_<lang>.go`).
   The id is `<prefix>:<slug>` — the prefix comes from `langspec` (e.g. `go`, `js`, `ts`).
2. For a security rule, add a **taxonomy** entry (description + CWE/OWASP + tags) and a
   **remediation** line in `internal/rules/taxonomy.go`. Unlisted rules fall back to their name.
3. Add a **fixture** under `testdata/<lang>bugfixture/` (or inline source) and a test:
   - `internal/rules/rules_test.go` / `taint_test.go` use `runRulesSrc(t, lang, src)` for inline checks.
   - `internal/scan/scanner_test.go` exercises the full pipeline over a fixture dir.
   Always include a **negative** case (the safe form must produce no finding).
4. `gofmt -w`, then `make test` and `make vet`.
5. `make rules-catalog` to regenerate `docs/RULES_CATALOG.md`.
6. Keep the self-scan green: `./bin/codepulse-scan -fail-on CRITICAL -exclude testdata,web .`
   must exit 0 (rules must not false-positive on this repo).

Aim for **low false positives**: prefer precise queries, and always test the safe variant.

## Adding a language

Add a `langspec.Spec` (node-kind maps) in `internal/langspec/`, register it in
`langspec.For`, wire `ForLanguage`/`Languages` in `internal/rules/registry.go`, and add a
fixture + test. The cognitive/cyclomatic complexity rules are appended automatically.

## Pull requests

- One focused change per PR; include tests; keep `make test`, `make vet`, and the web suite green.
- CI runs the Go suite, the dashboard build/test, and dogfoods the GitHub Action against this repo.
- Run `gofmt` (Go) before committing.
