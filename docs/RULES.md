# CodePulse — Rule Engine & Authoring

How rules are defined, compiled, and run; the authoring format; quality profiles;
and how we reach broad rule coverage without writing a JVM plugin per rule.

---

## 1. Design principles

1. **Declarative first.** Most rules should be a tree-sitter query plus a tiny bit of
   match logic — readable by anyone, no recompile to add a rule.
2. **Escape hatch when needed.** Some checks (numeric thresholds, cross-node
   relationships, dataflow-lite) need code. Allow an optional Go predicate or a
   full Go visitor rule, but keep those rare.
3. **Testable in isolation.** Every rule ships with positive/negative fixtures and is
   unit-tested in CI against pinned grammars.
4. **Portable taxonomy.** Rules carry type (BUG/VULN/SMELL/HOTSPOT), severity, CWE/OWASP
   tags, and a remediation estimate, so they slot into ratings & security reports.

---

## 2. Three rule kinds

| Kind | When to use | Mechanism |
|------|-------------|-----------|
| **Query rule** | Pattern is expressible as a syntax shape | tree-sitter `.scm` query + capture-based message/severity |
| **Query + predicate** | Shape + a condition the query language can't state (length, value, "X without sibling Y") | `.scm` query + named Go predicate referenced from YAML |
| **Visitor rule** | Genuinely complex (limited intra-procedural dataflow, symbol resolution) | pure Go implementing the `Rule` interface |

The goal is for ~80% of rules to be query-only, ~15% query+predicate, ~5% visitor.

---

## 3. Authoring format

A rule lives under `rules/<lang>/<rule-id>/` with three files:

```
rules/python/dangerous-eval/
├── rule.yaml         # metadata + how to run
├── query.scm         # tree-sitter query (for query / query+predicate kinds)
└── tests/
    ├── bad.py        # must produce findings (with // expect markers)
    └── good.py       # must produce none
```

### 3.1 `rule.yaml`

```yaml
id: python:dangerous-eval
language: python
name: "Use of eval() on untrusted input is dangerous"
type: VULNERABILITY            # BUG | VULNERABILITY | CODE_SMELL | HOTSPOT
severity: CRITICAL             # BLOCKER|CRITICAL|MAJOR|MINOR|INFO
tags: [security, injection]
cwe: ["CWE-95"]
owasp: ["A03:2021"]
remediation_min: 20            # base remediation effort, minutes
kind: query                    # query | query_predicate | visitor

# message templated from query captures (@names)
message: "Avoid eval(); it executes arbitrary code. Use ast.literal_eval or a safe parser."

# primary location capture; secondaries optional
location: "@call"
secondary_locations: []

# parameters surfaced in quality profiles (overridable per profile)
params:
  - key: allow_in_tests
    type: bool
    default: true
    description: "Don't flag eval() inside test files."

# for kind: query_predicate
predicate: ""                  # e.g. "stringLiteralLongerThan" with args below
predicate_args: {}
```

### 3.2 `query.scm`

```scheme
; flag calls to the builtin eval()
(call
  function: (identifier) @fn
  (#eq? @fn "eval")) @call
```

Findings are produced for each match of `@call`; `@fn` etc. are available to the
message template and predicates. Tree-sitter's built-in predicates (`#eq?`,
`#match?`, `#any-of?`) cover a lot before we ever need Go.

### 3.3 Predicate rules

When the query can match but a final decision needs logic, reference a registered
predicate:

```yaml
kind: query_predicate
predicate: stringLiteralLongerThan
predicate_args: { capture: "@msg", max: 120 }
```

```go
// internal/rules/predicates/string_len.go
func StringLiteralLongerThan(ctx PredicateCtx, args Args) bool {
    node := ctx.Capture(args.Str("capture"))
    return ctx.Text(node).Len() > args.Int("max")
}
```

Predicates are pure functions over `(captures, source, tree)` → bool/score, registered
by name. They keep the rule file declarative while allowing arbitrary checks.

### 3.4 Visitor rules

For the hard 5% (e.g. "variable assigned but never read within its function",
"resource opened on a path where it isn't closed"):

```go
type Rule interface {
    Meta() RuleMeta
    Check(ctx *AnalysisCtx) []Finding   // full access to tree, symbols, file
}
```

Visitor rules can use a lightweight, per-language **symbol/scope index** the engine
builds once per file (declarations, references, scopes) so multiple rules share it.
This enables a class of "unused"/"shadowed"/"used-before-defined" rules without each
rule re-walking the tree.

---

## 4. Engine execution model

Per file:
1. Parse → CST (cached for the file across all rules).
2. Build the shared **symbol index** if any active rule needs it.
3. For each active rule for the file's language:
   - Query/predicate rules: run the compiled `Query` via a `QueryCursor`, evaluate
     built-in + custom predicates per match, template the message, emit `Finding`s.
   - Visitor rules: call `Check(ctx)`.
4. Collect findings, attach severity/effort from the **active quality profile**
   (which may override the rule's defaults and set params), dedupe, and return.

Performance:
- Compile each rule's query **once** at startup, reuse across files.
- Group rules by language; only load grammars/queries for languages actually present.
- A single `QueryCursor` walk per query; the CST walk for metrics is separate but on
  the same cached tree.

---

## 5. Quality profiles

- A **quality profile** is a per-language named set of active rules with their
  severities and parameters (see DATA_MODEL `quality_profile`/`profile_rule`).
- Ships with a **built-in default** profile per language ("CodePulse Way") that we
  maintain; users can **copy & customize** or create profiles that **inherit** from a
  parent (override/extend without losing upstream updates).
- A project binds one profile per language. Changing a profile triggers re-evaluation
  on the next analysis (not retroactive rewrites of history).
- Profiles are import/export-able as YAML for version control & sharing.

### Implemented today (scanner-side)

The scanner reads a **quality-profile file** (`.codepulse.yml`/`.codepulse.yaml`,
auto-discovered in the scan root, or passed via `-profile <path>`). YAML or JSON:

```yaml
# Turn off rules you don't want
disable:
  - js:var-declaration
  - go:todo-comment
# Promote/demote a rule's severity
severity:
  go:panic-usage: BLOCKER      # BLOCKER|CRITICAL|MAJOR|MINOR|INFO
  py:bare-except: MINOR
# Override the cyclomatic-complexity threshold (<lang>:high-complexity), all langs
complexityThreshold: 20        # default 15
```

Unknown rule ids, invalid severities, and a negative threshold are rejected at
load time (fail-loud, not silently ignored). The profile is applied before the
engine runs, so it also affects `-fail-on` and any server-side quality gate fed
by the report. Named/inheriting profiles and additional per-rule parameters
remain future work.

### Inline suppression

A trailing comment on a flagged line suppresses findings there — useful for
intentional, reviewed exceptions:

```go
result := append(s, x)          // codepulse:ignore go:discarded-append (kept for the side effect... actually don't)
password := mustLoadFromVault() // codepulse:ignore   (suppresses ALL rules on this line)
risky()                         // NOSONAR             (SonarQube-compatible alias)
```

- `codepulse:ignore` with no ids suppresses every rule on that line.
- `codepulse:ignore id1 id2` suppresses only the listed rule ids.
- `NOSONAR` suppresses all rules on that line (Sonar compatibility).

Suppression matches the finding's **start line**. Suppressed findings are
dropped from the report (so they don't affect `-fail-on` or gates) but counted
in `summary.suppressedFindings` and printed in the CLI summary, so suppressions
stay visible rather than silent.

---

## 6. Rule sourcing strategy (how we get coverage fast)

Writing thousands of rules from scratch is the multi-year trap. Strategy:

1. **First-party query rules** for high-value, language-specific checks (the
   "CodePulse Way" default profiles) — focused, well-tested, low false-positive.
2. **Import & normalize external analyzers via SARIF** (gosec, Bandit, ESLint,
   golangci-lint, Semgrep, etc.) as a first-class path: users run their existing
   linters; CodePulse consolidates, tracks, and gates on the results in one dashboard.
   This delivers breadth on day one while first-party rules grow.
3. **Semgrep-rule interop (investigation):** Semgrep's pattern syntax is popular and
   permissively-licensed rules exist; explore a transl(or adapter that shells out to
   Semgrep) so its community rulesets are usable inside CodePulse. (Phase 3.)
4. **Community rule contributions:** because rules are YAML + `.scm` + fixtures, the
   contribution bar is a PR, not a plugin SDK. A `rules/` directory + a test harness
   (`codepulse rule test`) is the whole on-ramp.

This "integrate, don't reinvent" stance is the pragmatic difference-maker: CodePulse is the
**platform** (tracking, history, gates, dashboard, multi-language consolidation), and
it both ships good first-party rules *and* ingests the broader OSS analyzer ecosystem.

---

## 7. Rule testing harness

```
$ codepulse rule test rules/python/dangerous-eval
✓ bad.py    2 findings (expected 2)
✓ good.py   0 findings (expected 0)
```

- Fixtures use `# noqa`-style **expectation markers** (`# expect: python:dangerous-eval`)
  on the line a finding is expected; the harness asserts exact match (no missing, no
  extra) → guards against false positives *and* regressions.
- The full corpus runs in CI against the **pinned grammar versions**, so a grammar bump
  that changes node names fails loudly with the exact rules to fix.

---

## 8. Severity, type & remediation

- **Type** drives which rating a rule affects (BUG→Reliability, VULNERABILITY→Security,
  CODE_SMELL→Maintainability; HOTSPOT→manual review workflow, no rating impact until
  reviewed).
- **Severity** (BLOCKER…INFO) drives gate conditions like `new_blocker_issues > 0`.
- **Remediation effort** (minutes) sums into technical debt → maintainability rating &
  debt ratio. Can be constant or a function of the finding (e.g. per duplicated block).
- **Security hotspots** are deliberately *not* auto-failures: they mark
  security-sensitive code requiring human review (`TO_REVIEW` → `SAFE`/`FIXED`), which
  keeps the security gate from being noisy while still surfacing risk.
