# CodePulse — Roadmap

Phased plan from a runnable MVP to SonarQube feature parity, plus a feature
comparison matrix and the key risks. Each phase is shippable on its own.

---

## Guiding sequencing principle

Build the **vertical slice** first (one language end-to-end: scan → store → dashboard →
gate), then **widen** (more languages, more rules) and **deepen** (incremental analysis,
PR decoration, SCM integrations). Always keep "CodePulse scans CodePulse" green in CI.

---

## Phase 0 — Foundations (design + skeleton)  ✅ *this repo*
- Architecture, data model, rule format, roadmap (these docs).
- Decide bindings (`go-tree-sitter`), pin first grammars (Go + Python).
- Repo scaffolding, CI, `docker compose` skeleton, OpenAPI stub.

**Exit:** a `docker compose up` brings up empty server + Postgres + blank dashboard; `codepulse-scan --version` runs.

## Phase 1 — Vertical slice (single language, end-to-end)

> **Progress:** scanner core ✅ — `codepulse-scan` walks a repo, parses Go via
> tree-sitter, runs built-in rules (panic usage, TODO/FIXME, empty blocks, high
> cyclomatic complexity), computes size/complexity/comment metrics, and emits
> SARIF 2.1.0 + internal JSON. Unit + e2e tests green; dogfoods on its own source.
> **Next:** grow the rule set, then the server + dashboard.

- `codepulse-scan`: walk + ignore rules, **Go** parsing, ~15 first-party Go query rules,
  size + cyclomatic complexity metrics, SARIF + internal report output.
- `codepulse-server`: token auth, ingest (synchronous first), persist analysis/issues/measures,
  basic issue tracking (line-hash matching).
- `codepulse-web`: projects list, project home, issues browser (filter by type/severity/rule),
  single measures view.
- One built-in quality profile + a default quality gate; gate evaluated & shown.

**Exit:** point it at a Go repo in CI, see issues + measures + gate pass/fail in the dashboard.

## Phase 2 — Breadth & the metrics that matter

> **Progress:** multi-language core ✅ — added a `langspec` abstraction (per-language
> node-kind mappings) so the metrics + rule engine are language-agnostic. **Python**
> plus **JavaScript and TypeScript** are now supported alongside Go (per-language
> rule sets incl. eval/exec, TODO/FIXME, bare-except, debugger, high-complexity, and
> **security hotspots** for command execution), with cognitive complexity per language. Mixed-language
> scans aggregate correctly. **Duplication detection** (token-window clone finder) and
> **coverage import** (LCOV / Go coverprofile / Cobertura, suffix-matched onto files)
> are implemented and fold into per-file + project metrics. **Ratings** (reliability,
> security, maintainability) + **technical debt** are derived from findings/size.
> **`codepulse-server`** now exists: HTTP API (projects, analysis ingest, issues,
> measures, quality-gate status) over a pluggable store (in-memory impl with
> issue-tracking carry-over), and **quality-gate evaluation** (default "CodePulse Way"
> gate). Full scan→upload→gate pipeline verified against the running binaries; e2e
> tested via httptest. A **PostgreSQL-backed store** (pgx) now implements the same
> interface with SQL-level issue tracking, **integration-tested against a real
> Postgres** (PG 18 via an embedded binary; carry-over + fixed detection verified);
> `codepulse-server` selects it via `DATABASE_URL`. **docker-compose** + Dockerfile
> ship for self-host. The **Vue 3 dashboard** (`web/`) is built: projects list, project
> detail (gate badge + A–E ratings + measures), and an issues browser, wired to the API.
> Vitest unit/component/view tests (12) + production build green. **Issue workflow**
> (assign, comment, transition with sticky false-positive/won't-fix) and **security-hotspot
> review workflow** (TO_REVIEW → REVIEWED: SAFE/FIXED/ACKNOWLEDGED) are implemented in
> both stores with HTTP endpoints; httptest + real-Postgres integration tests cover them.
> **New-code period** ✅ — the scanner blames each finding to its introducing commit
> (author + date) and flags `isNew` within an N-day window (`-new-code-days`); the
> report carries `new_*` measures and the gate has clean-as-you-code conditions
> (`new_vulnerabilities`, `new_blocker_issues`). e2e tested against a real throwaway
> git repo (old vs new commits). **Branch/PR analysis** ✅ — analyses/issues/hotspots
> are namespaced per branch; ingest takes `?branch=&base=` and returns new-vs-base issue
> counts; `GET /issues/new` lists PR-introduced issues. **PR decoration** ✅ — a GitHub
> commit-status decorator (enabled via `GITHUB_TOKEN`) posts the gate result; httptest +
> real-Postgres integration cover branch isolation + the new-issue diff; decorator
> unit-tested against a fake API. **Next (Phase 4):** auth (tokens/RBAC) + SSO, scale, dataflow.

- Add **Python, JavaScript, TypeScript, Java** grammars + starter rule sets.
- Cognitive complexity, comment density, **duplication detection**, coverage import
  (Cobertura/LCOV/JaCoCo/Go), test results import.
- Ratings (reliability/security/maintainability) + technical debt.
- Async ingest via Postgres job queue + workers.
- Quality profile management UI; quality gate editor; measures treemap & drilldown.
- **External SARIF import** (gosec/ESLint/Bandit/golangci-lint) — instant breadth.

**Exit:** multi-language project shows consolidated issues (first-party + imported), full
metric domains, ratings, and a working clean-as-you-code gate.

## Phase 3 — "New code" & developer workflow
- **New-code period** definitions + git blame attribution; `new_*` measures & gate
  conditions; clean-as-you-code default gate.
- **Branch & pull-request analysis**; PR shows only newly-introduced issues.
- **PR decoration & status checks** for GitHub / GitLab / Bitbucket; webhooks.
- **Incremental analysis** in the scanner (only changed files; merge with last snapshot).
- Issue workflow: assign, comment, false-positive/won't-fix stickiness, changelog UI.
- Activity/trends charts; security hotspots review workflow.
- Semgrep-rule interop investigation.

**Exit:** a team can adopt CodePulse on a legacy repo, gate PRs on new code only, and triage.

## Phase 4 — Scale, polish, ecosystem

> **Progress:** **AuthN/Z** ✅ — hashed API tokens (project-scoped `scan`/`viewer`,
> global `admin`); opt-in enforcement (enabled by a bootstrap admin token / 
> `CODEPULSE_ADMIN_TOKEN`); RBAC guards on every endpoint (admin-only project/token
> management + triage; scan-token ingest restricted to its project; reads scoped to
> project). `POST /tokens` mints credentials (secret shown once). e2e tested
> (401/403/200 matrix). **Java** is now the 5th language (rules: empty-catch, System.exit,
> process-exec hotspot, TODO, high-complexity). **External-analyzer SARIF import** ✅ —
> third-party results (gosec/ESLint/Bandit/…) are parsed and merged as namespaced
> `external:<tool>:<rule>` findings (`-import-sarif`), unit-tested. **Portfolio/aggregation**
> ✅ (`GET /portfolio`: every project's latest gate + ratings + size) and **retention/pruning**
> ✅ (`POST /projects/{key}/prune?keep=N`, both stores) are done and e2e tested.
> **Next:** SSO (OIDC login) and a documented dataflow integration (Semgrep/CodeQL via SARIF).
- AuthN/Z: local users + **OIDC/SAML/GitHub** SSO, groups, fine-grained RBAC.
- Performance: partitioning, retention/pruning, read replicas; horizontal worker scaling.
- More languages (C/C++, C#, Ruby, PHP, Rust, Kotlin, Bash, etc.).
- IDE feedback via LSP diagnostics export / SARIF; CLI `--fix` for autofixable rules.
- i18n, accessibility, theming.
- Portfolio/aggregation views across many projects; notifications (email/Slack).
- Investigate **WASM grammars (wazero)** to drop CGo and simplify cross-compilation.
- Optional deeper analysis: pluggable taint/dataflow engine integration (CodeQL/Semgrep)
  for security-critical rules.

**Exit:** production-grade self-host suitable for an org with many repos and SSO.

---

## SonarQube feature comparison (target state)

| Capability | SonarQube (CE / paid) | CodePulse target |
|---|---|---|
| Multi-language analysis | CE limited; many langs paid | **All langs OSS** (tree-sitter) — *P1–P4* |
| Bugs / Vulnerabilities / Code smells | ✅ | ✅ *P1–P2* |
| Security hotspots | ✅ | ✅ *P3* |
| Metrics (LOC, complexity, duplication) | ✅ | ✅ *P1–P2* |
| Cognitive complexity | ✅ | ✅ *P2* |
| Coverage / test import | ✅ | ✅ *P2* |
| Quality profiles (inherited, custom) | ✅ | ✅ *P2* |
| Quality gates | ✅ | ✅ *P1 basic → P3 new-code* |
| Clean-as-you-code / new-code period | ✅ | ✅ *P3* |
| Branch & PR analysis | **paid** | ✅ **OSS** *P3* |
| PR decoration (GH/GL/BB) | **paid** | ✅ **OSS** *P3* |
| Issue tracking across analyses | ✅ | ✅ *P1→P3* |
| External analyzer (SARIF) import | partial | ✅ **first-class** *P2* |
| Rule authoring | Java plugin SDK | **YAML + tree-sitter query** *P1* |
| SSO (SAML/OIDC) | **paid** | ✅ **OSS** *P4* |
| Portfolio / aggregation | **paid** | ✅ *P4* |
| Taint/dataflow security | **paid, deep** | integrate (CodeQL/Semgrep) *P4* |
| Deployment weight | JVM, heavier | single Go binary + Postgres |
| License | LGPL + commercial editions | **Apache-2.0, no gated features** |

**Deliberately positioned advantages:** branch/PR analysis, PR decoration, SSO, and
portfolios are *paid* in SonarQube — CodePulse keeps them open. The trade-off we accept early
is **shallower security dataflow** (tree-sitter is syntactic); we close that gap by
integrating best-of-breed OSS engines rather than reimplementing taint analysis.

---

## Top risks & mitigations

| Risk | Mitigation |
|---|---|
| **Grammar version drift** breaks queries silently | Pin grammar SHAs per release; run full rule corpus in CI against pinned grammars; `langspec` abstraction for metrics |
| **CGo cross-compilation pain** | Per-platform release matrix with grammars compiled in; investigate WASM grammars (wazero) to go pure-Go (P4) |
| **Rule coverage takes years** | Integrate external SARIF + Semgrep rules for breadth; first-party rules focus on quality not quantity |
| **Issue-tracking instability** (resurrected/duplicated issues) | Content-hash + structural matching, not line numbers; large regression corpus of real diffs |
| **False-positive fatigue** | Every rule ships good/bad fixtures with exact-match assertions; conservative default profiles; easy false-positive marking that sticks |
| **Performance on monorepos** | Parallel scanner, incremental analysis, async ingest queue, table partitioning + retention |
| **Scope creep vs SonarQube's 15-year head start** | Vertical-slice-first; "integrate don't reinvent"; ship each phase independently useful |

---

## Definition of done for v1.0 (public)

- ≥5 languages with maintained default profiles.
- Branch + PR analysis with GitHub/GitLab decoration.
- Clean-as-you-code gate working on real legacy repos.
- External SARIF consolidation.
- SSO + RBAC.
- `docker compose up` self-host in < 5 minutes; documented upgrade path.
- CodePulse analyzes its own codebase in CI and passes its own gate.
