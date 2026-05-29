# CodePulse — Architecture

This document describes the system components, the scanner pipeline, tree-sitter
integration, the server/API, and deployment. It is the canonical technical
reference for the project.

---

## 1. Goals & non-goals

### Goals
- **Multi-language** static analysis from a single engine (tree-sitter grammars).
- **Three issue families:** bugs, vulnerabilities, code smells; plus *security hotspots* (review-required, not auto-flagged).
- **Metrics over time:** LOC, cyclomatic & cognitive complexity, duplication, comment density, test coverage import, and derived ratings (maintainability, reliability, security).
- **Quality gates:** configurable pass/fail conditions evaluated on each analysis, with a strong emphasis on the **"new code"** period (clean-as-you-code).
- **CI-native:** one static binary, SARIF output, exit codes, PR decoration hooks.
- **Self-hostable:** `docker compose up` → working instance. Single Postgres dependency.
- **Authoring without a JVM:** rules are YAML + tree-sitter `.scm` queries + optional small Go predicates, not full plugin jars.

### Non-goals (initially)
- Deep dataflow / taint analysis across files (Phase 4+; tree-sitter is syntactic). For serious taint, we integrate with CodeQL/Semgrep rather than reimplement.
- Build-system integration / bytecode analysis.
- IDE plugins (SARIF + LSP-diagnostics export covers most of this for free early on).
- Replacing compilers' own type checking.

---

## 2. Component overview

```
                          ┌──────────────────────────────────────────┐
                          │              codepulse-scan (CLI)             │
                          │                                           │
  repo on disk ─────────► │  walk → parse → analyze → measure → emit  │ ──► SARIF / internal JSON
                          │     (tree-sitter)   (rules)  (metrics)    │       │
                          └──────────────────────────────────────────┘       │ upload (HTTP)
                                                                              ▼
   ┌──────────────────────────────────────────────────────────────────────────────┐
   │                                codepulse-server (Go)                               │
   │                                                                                │
   │   HTTP API ──► ingest queue ──► analysis worker ──► issue tracker ──► gate eval │
   │      │                                  │                  │             │      │
   │      │                                  ▼                  ▼             ▼      │
   │      │                             PostgreSQL  (projects, analyses, issues,     │
   │      │                              measures, rules, profiles, gates, users)    │
   │      ▼                                                                          │
   │   REST/JSON  ◄──────────────────────────────────────────────────────────────  │
   └────────┬───────────────────────────────────────────────────────────────────────┘
            │
            ▼
   ┌──────────────────┐
   │  codepulse-web (Vue) │  projects overview · issue browser · measures/trends · gate · admin
   └──────────────────┘
```

### 2.1 `codepulse-scan` — the scanner CLI (Go)
The only thing that touches user source code. Stateless. Runs locally or in CI.

Responsibilities:
1. **Discover** files (respect `.gitignore`, `.codepulseignore`, include/exclude globs, max file size).
2. **Detect language** per file (extension + shebang + content heuristics).
3. **Parse** each file with the matching tree-sitter grammar → concrete syntax tree (CST).
4. **Run rules** against the tree → issues.
5. **Compute metrics** (LOC, complexity, comments) per file; run **duplication** detection across the file set.
6. **Import external reports** (coverage XML/LCOV, third-party SARIF, linter output) and normalize them.
7. **Emit** results: SARIF 2.1.0 to stdout/file *and/or* upload the internal report to a server.
8. **Exit code** reflects the local quality-gate verdict (for CI failure), if a gate is configured/cached.

Key properties:
- **Parallel** across files (worker pool, GOMAXPROCS-bound).
- **Incremental** mode: given a base commit, only re-analyze changed files + recompute affected metrics; merge with the server's last full snapshot. (Phase 3.)
- **Hermetic**: grammars are compiled into the binary (CGo) or loaded from a versioned cache; no network needed to analyze.

### 2.2 `codepulse-server` — API + workers (Go)
Stateless HTTP layer + background workers, backed by Postgres.

Responsibilities:
- Accept uploaded analysis reports (authenticated by project token).
- Persist a new **analysis** (an immutable snapshot for a project at a commit).
- **Track issues across analyses** (match new findings to existing open issues; carry over status like "won't fix"/"false positive"; mark fixed). See DATA_MODEL.md §4.
- Compute & store **measures** at file/directory/project granularity.
- Evaluate the project's **quality gate** → status + failing conditions.
- Serve the dashboard's read API and admin/config API.
- Webhooks / PR decoration (GitHub/GitLab/Bitbucket) — post gate status back.

Internally split into:
- `api` — HTTP handlers (chi/echo router), auth, validation.
- `ingest` — receives reports, enqueues (in-process queue → Postgres-backed job table for durability).
- `worker` — consumes ingest jobs: persistence, issue tracking, measure aggregation, gate eval.
- `store` — Postgres data access (sqlc-generated queries; no heavy ORM).

> **Why a queue?** Large monorepo uploads can be tens of MB and produce 100k+ issues. Decoupling ingest (fast ACK) from processing keeps the API responsive and lets us retry/scale workers.

### 2.3 `codepulse-web` — dashboard (Vue 3 + Vite)
SPA talking to the REST API. Views:
- **Projects overview:** grid of projects with gate status, key ratings, last analysis.
- **Project home:** quality gate result, "new code" vs "overall" toggle, headline measures.
- **Issues browser:** faceted filtering (type, severity, rule, file, status, assignee, "new code only"), code snippet view with the offending lines highlighted, issue actions (confirm, resolve, false-positive, won't-fix, assign, comment).
- **Measures:** treemap / drilldown by directory & file; metric domains (Reliability, Security, Maintainability, Coverage, Duplications, Size, Complexity).
- **Activity / trends:** time series of measures across analyses; event annotations (gate failures, version bumps).
- **Security hotspots:** review workflow (to review / acknowledged / fixed / safe).
- **Admin:** projects, quality profiles, quality gates, users/permissions, tokens, global settings.

State via Pinia; data fetching via a typed API client generated from the server's OpenAPI spec.

---

## 3. Scanner pipeline (detail)

```
 files ──► [language router] ──► [parser pool] ──► CST per file
                                       │
                  ┌────────────────────┼─────────────────────┐
                  ▼                    ▼                     ▼
            [rule engine]        [metric collectors]   [token stream]
             issues per file      LOC/CC/cognitive/      (for duplication
                  │               comments per file       hashing)
                  │                    │                     │
                  └──────────┬─────────┴──────────┬──────────┘
                             ▼                     ▼
                      [report builder]      [duplication detector]
                             │                     │
                             └──────────┬──────────┘
                                        ▼
                                [report: SARIF + internal JSON]
```

### 3.1 Language detection
Order of precedence: explicit config override → shebang (`#!`) → extension map → content sniffing (small set of regex heuristics for ambiguous extensions like `.h`, `.m`, `.ts` vs `.tsx`). Unknown languages: counted for LOC only (or skipped), never errored.

### 3.2 Parsing
- One tree-sitter `Parser` per worker goroutine (parsers are not thread-safe; pool them).
- Grammars linked via CGo. We vendor a curated set and pin versions per release (grammar ABI matters).
- Parse errors don't abort — tree-sitter produces a partial tree with `ERROR` nodes. We record a `parse-error` info-level finding and still run rules on the recoverable subtree.
- File-size / parse-time guards to avoid pathological inputs.

### 3.3 Rule engine
See [RULES.md](RULES.md) for the authoring format. At runtime:
- Each rule compiles to either (a) a tree-sitter **query** (`.scm`) with capture-based match conditions, or (b) a **query + Go predicate** for logic the query language can't express (e.g. "string literal longer than N", numeric comparisons, cross-node relationships), or (c) a pure-Go **visitor** rule for the rare complex case.
- The engine runs all enabled queries for a language in a **single tree walk** where possible (tree-sitter `QueryCursor` per query, but shared tree), collecting captures, then evaluates predicates.
- Each match → an **issue** with: rule id, message (templated from captures), primary location (file + byte/row/col range), optional secondary locations (e.g. "variable defined here"), severity, type, and effort estimate (remediation cost in minutes).

### 3.4 Metrics collectors
Computed during/after the tree walk:
- **Size:** lines, lines of code (non-blank, non-comment), statements, functions, classes.
- **Complexity:** *cyclomatic* (count decision points via node-type sets per language) and *cognitive complexity* (nesting-weighted, à la SonarSource's spec) — both defined per language via a small config mapping node types → increments.
- **Comments:** comment lines, comment density, detection of commented-out code (heuristic).
- **Documentation/API:** public API count & documented ratio (where the grammar exposes it).

Per-language metric definitions live in `langspec/<lang>.yaml` (which node kinds are functions, which are branch points, etc.), so adding a language doesn't require new Go code for metrics.

### 3.5 Duplication detection
- Tokenize each file (from the CST, normalizing identifiers/literals optionally) into a token stream.
- Rolling-hash (Rabin–Karp) over sliding windows of N tokens; index hashes; report blocks of ≥ M duplicated tokens spanning ≥ K lines across one or more files (SonarQube-style: ≥10 lines / ≥100 tokens defaults, tunable).
- Output: duplicated blocks, duplicated lines %, duplicated files count.

### 3.6 External report import
Normalizers for common formats → internal model:
- **Coverage:** Cobertura XML, JaCoCo XML, LCOV, Go coverprofile, Istanbul/lcov, `coverage.py` XML.
- **Test results:** JUnit XML, etc. (for test count/duration metrics).
- **Third-party issues:** any SARIF 2.1.0 producer (ESLint, gosec, Bandit, golangci-lint, Semgrep…) imported as issues attributed to an external rule namespace, so users can consolidate everything in one dashboard.

### 3.7 Output
- **SARIF 2.1.0**: portable, consumable by GitHub code scanning, IDEs, etc.
- **Internal report (`codepulse-report.json`)**: a richer superset (measures, duplication blocks, coverage, language stats, scanner metadata, base commit) used for server upload. Versioned schema.

---

## 4. Tree-sitter integration

- **Bindings:** `github.com/smacker/go-tree-sitter` (or maintained fork) via CGo. Evaluate `go-tree-sitter` ABI compatibility per grammar; pin grammar commit SHAs.
- **Grammar set (Phase 1–2):** Go, Python, JavaScript, TypeScript, Java. (Phase 3+: C/C++, C#, Ruby, PHP, Rust, Kotlin, Bash, etc.)
- **Queries:** rules and some metrics use tree-sitter's S-expression query language stored in `.scm` files; this keeps most analysis declarative and language-portable in spirit (though queries are per-grammar because node names differ).
- **Versioning risk:** grammar node-type names change between versions and break queries. Mitigation: pin grammar versions per CodePulse release; run the full rule test corpus in CI against the pinned grammars; a `langspec` abstraction layer maps "logical" node categories → concrete node kinds so metric code is insulated.
- **Build:** CGo means cross-compilation needs care. We produce per-platform release binaries (linux/amd64, linux/arm64, darwin/arm64, windows/amd64) via a build matrix; grammars compiled in. A pure-Go fallback (WASM grammars via wazero) is a Phase 4 investigation to drop CGo.

---

## 5. API surface (representative)

Auth: project-scoped **analysis tokens** (for `codepulse-scan` upload) and **user sessions/PATs** (for dashboard/admin). All under `/api/v1`.

**Ingest**
- `POST /analyses` — upload a report (multipart or gzipped JSON). Returns `analysisId`, `task` (async). Auth: project token.
- `GET  /tasks/{id}` — ingest/processing task status.

**Read (dashboard)**
- `GET /projects` — list with gate status + headline measures.
- `GET /projects/{key}` — project detail.
- `GET /projects/{key}/analyses` — analysis history (paged).
- `GET /issues?project=&types=&severities=&rules=&statuses=&inNewCodePeriod=&assignee=&p=&ps=` — faceted issue search.
- `GET /issues/{id}` — issue with locations, snippet, changelog, comments.
- `GET /measures?project=&metrics=&component=` — measures for a component (file/dir/project).
- `GET /measures/history?project=&metrics=&from=&to=` — time series.
- `GET /components/tree?project=&strategy=&metricSort=` — component drilldown (treemap data).
- `GET /hotspots?project=&status=` — security hotspots.
- `GET /quality-gates/status?project=` — gate result + conditions.

**Issue actions**
- `POST /issues/{id}/transition` — confirm/resolve/reopen/falsepositive/wontfix.
- `POST /issues/{id}/assign`, `POST /issues/{id}/comments`.

**Admin/config**
- `CRUD /quality-profiles`, `/quality-gates`, `/rules` (activate/deactivate, set severity), `/projects`, `/users`, `/groups`, `/permissions`, `/tokens`, `/settings`.

A machine-readable **OpenAPI 3** spec is the source of truth; the Vue client and docs are generated from it.

---

## 6. Quality gates & "new code"

- A **quality gate** is a named set of **conditions** on metrics, e.g.:
  - `new_coverage < 80%` → ERROR
  - `new_duplicated_lines_density > 3%` → ERROR
  - `new_blocker_issues > 0` → ERROR
  - `new_maintainability_rating worse than A` → ERROR
- The default gate ("Clean as You Code") focuses on **new code** — code added/changed since a baseline (previous version, a date, a number of days, or a reference branch). This lets teams adopt CodePulse on legacy codebases without an unwinnable backlog.
- "New code" attribution uses SCM blame (git) collected by the scanner: each issue/line is tagged with the introducing commit/date; conditions on `new_*` metrics only consider lines within the new-code period.
- Gate evaluation runs server-side after each analysis; the result is stored on the analysis and posted to PRs via decoration.

---

## 7. Deployment

**Default (self-host):** `docker compose` with three services:
- `codepulse-server` (API + embedded workers; can scale workers separately later)
- `postgres`
- `codepulse-web` served as static assets behind the server or via the same binary (embed with `embed.FS`).

The scanner is distributed as a standalone binary / container image and a GitHub Action / GitLab template.

**Scaling path:** server is stateless → run N replicas behind a load balancer; workers can be split into a separate deployment consuming the Postgres job table; Postgres is the only stateful component (add read replicas for dashboard-heavy installs). No message broker required at small/medium scale (Postgres `SKIP LOCKED` job queue); Redis/NATS optional later.

**Config:** 12-factor env vars; secrets via env/file; object storage (S3-compatible) optional for raw report archival.

---

## 8. Repository layout (monorepo)

```
codepulse/
├── README.md
├── docs/                     # these design docs
├── cmd/
│   ├── codepulse-scan/           # scanner CLI entrypoint
│   └── codepulse-server/         # server entrypoint
├── internal/
│   ├── scan/                 # walk, language detection, orchestration
│   ├── parse/                # tree-sitter parser pool, grammar registry
│   ├── rules/                # rule engine, loader, registry
│   ├── metrics/              # size, complexity, comments
│   ├── dup/                  # duplication detector
│   ├── importers/            # coverage/junit/sarif normalizers
│   ├── report/               # SARIF + internal report (de)serialization
│   ├── api/                  # HTTP handlers, OpenAPI
│   ├── ingest/               # upload + job queue
│   ├── worker/               # processing, issue tracking, gate eval
│   ├── store/                # Postgres (sqlc), migrations
│   └── domain/               # core types (Issue, Rule, Measure, Gate…)
├── langspec/                 # per-language node-kind mappings (yaml)
├── rules/                    # rule definitions (yaml + .scm), per language
│   ├── go/ python/ js/ ts/ java/ ...
├── grammars/                 # vendored tree-sitter grammars (pinned)
├── web/                      # Vue 3 + Vite dashboard
├── deploy/                   # docker-compose, Dockerfiles, k8s manifests, GH Action
└── testdata/                 # fixture projects + rule unit-test corpus
```

---

## 9. Cross-cutting concerns

- **Determinism:** same inputs → identical report (stable ordering, no wall-clock in IDs) so diffs/issue-tracking are reliable.
- **Performance budget (target):** ~100k LOC analyzed in < 30s on a 4-core CI runner (Phase 2 goal); incremental re-scan of a PR in < 5s.
- **Security of the platform itself:** scanner never executes analyzed code; reports are validated/size-capped; tokens hashed at rest; RBAC on every API; the project eats its own dog food (CodePulse scans CodePulse in CI).
- **Observability:** structured logs, Prometheus metrics, OpenTelemetry traces on server.
- **Internationalization:** rule messages support templating now; UI i18n is Phase 4.

See [DATA_MODEL.md](DATA_MODEL.md), [RULES.md](RULES.md), and [ROADMAP.md](ROADMAP.md).
