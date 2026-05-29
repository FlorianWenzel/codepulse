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
- Async ingest ✅ — opt-in worker-pool queue (`CODEPULSE_INGEST_WORKERS`): ingest returns 202 + task id, `GET /tasks/{id}` reports status; same path is durable-PG-queue-ready.
- Quality gate editor ✅ (configurable gates: create/list, assign per project; ingest evaluates the project's gate). Gate management UI ✅ (dashboard /gates: list, create with a condition builder, assign per project). Measures treemap & drilldown ✅.
- **External SARIF import** (gosec/ESLint/Bandit/golangci-lint) — instant breadth.

**Exit:** multi-language project shows consolidated issues (first-party + imported), full
metric domains, ratings, and a working clean-as-you-code gate.

## Phase 3 — "New code" & developer workflow
- **New-code period** definitions + git blame attribution; `new_*` measures & gate
  conditions; clean-as-you-code default gate.
- **Branch & pull-request analysis**; PR shows only newly-introduced issues.
- **PR decoration & status checks** for GitHub / GitLab / Bitbucket; webhooks.
- **Incremental analysis** ✅ — `-since <ref>` scans only files changed since a git ref (server-side issue tracking merges across analyses).
- Issue workflow: assign, comment, false-positive/won't-fix stickiness, changelog UI.
- Activity/trends charts ✅ (`/measures/history` + dashboard sparkline); security hotspots review workflow ✅ (backend + dashboard panel).
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
> **SSO (OIDC)** ✅ — `/auth/login` → IdP → `/auth/callback` exchanges the code, reads the
> user's email, and mints a CodePulse token (admin if allow-listed, else a global read-only
> viewer); state-cookie CSRF guard; configured via `CODEPULSE_OIDC_*`; tested against a fake
> IdP. **Notifications webhook** ✅ (`CODEPULSE_WEBHOOK_URL`; posts gate result per analysis,
> tested). **7 languages** now (added **Ruby, Rust**). **Dataflow integration**: consumed via
> the external-analyzer SARIF import (run Semgrep/CodeQL, feed their SARIF with `-import-sarif`).
> **C, Bash, C++, C#, PHP, Kotlin** added → **13 languages**. **LSP diagnostics export** (`-format lsp`) for IDE
> integration. The v1.0 Definition-of-Done checklist below is fully met; remaining items are
> post-v1.0 polish (yet more languages, richer rule sets, WASM grammars, i18n/theming).
- AuthN/Z: local users + **OIDC/SAML/GitHub** SSO, groups, fine-grained RBAC.
- Performance: partitioning, retention/pruning, read replicas; horizontal worker scaling.
- More languages (C/C++, C#, Ruby, PHP, Rust, Kotlin, Bash, etc.).
- IDE feedback via LSP diagnostics export / SARIF ✅. **Dedicated IDE plugins (SonarLint-style) are out of scope** — see Phase 5.
- i18n, accessibility, theming.
- Portfolio/aggregation views across many projects; notifications (email/Slack).
- Investigate **WASM grammars (wazero)** to drop CGo and simplify cross-compilation.
- Optional deeper analysis: pluggable taint/dataflow engine integration (CodeQL/Semgrep)
  for security-critical rules.

**Exit:** production-grade self-host suitable for an org with many repos and SSO.

---

## Phase 5 — Toward SonarQube parity (depth)

Phases 0–4 reached feature **breadth**; this phase closes the **depth** gap with SonarQube.
Ordered by leverage.

### 1. Rule coverage — *the* priority
- Greatly expand first-party rule sets, focused on **JavaScript/TypeScript, Java, and Go**
  (then Python), growing from a handful toward tens→hundreds of rules per language.
- Every rule ships good/bad fixtures + exact-match tests to keep false positives low.
- Cover correctness/bug patterns, security, concurrency, resource & error handling, API
  misuse, performance, and maintainability. Track coverage vs SonarQube's catalogue per language.

### 2. Analysis sophistication (semantic + dataflow)
- Per-language **symbol/scope index** (declarations, references, scopes) shared across rules,
  enabling semantic rules (unused / shadowed / used-before-defined, etc.).
- **Intra-procedural dataflow + lightweight taint analysis** (source → sink) for real security
  findings (injection, XSS, SSRF, path traversal) — beyond today's syntactic matches.
- Type-aware checks where grammar/imports permit. Keep **Semgrep/CodeQL via SARIF** as the
  deep-engine path for what we don't implement natively.

### 3. Rule content & security reporting
- Rich rule metadata: full **descriptions, remediation guidance, code examples**, severity
  rationale, tags — served via the API and rendered in the dashboard rule/issue views.
- **CWE / OWASP Top 10 (+ CWE Top 25)** mappings on rules, plus an OWASP-style **security
  report** per project. Adopt a clean-code-style issue taxonomy.

### 4. CI/CD — premade GitHub Action (like SonarQube's scan action) ✅
- **Shipped:** composite GitHub Action at repo root (`action.yml`, used as
  `FlorianWenzel/codepulse@v1`) — builds the scanner, runs the analysis, and **enforces the
  quality gate** (local `-fail-on`, or server mode: upload branch/PR-aware + fail on gate
  ERROR via `deploy/ci/gate.sh`). Dogfooded by a CI job (`uses: ./`). README has the snippet.
  **Next:** publish to the Actions Marketplace; add a GitLab CI template.

### 5. OIDC (extend what's shipped)
- OIDC **SSO login is already implemented** (`/auth/login` → `/auth/callback`; admin/viewer
  mapping; `CODEPULSE_OIDC_*`). Next: provider **presets** (Google, GitHub, Okta/Keycloak,
  Azure AD), group → role mapping, and **GitHub Actions OIDC keyless auth** so the Action
  uploads with a short-lived OIDC token instead of a static project token.

### More languages
- Keep widening via `langspec` (C++/C#/PHP/Kotlin/Scala/Swift already added; next Go templates,
  Lua, Elixir, …) — secondary to rule **depth** above.

### Explicitly out of scope
- **IDE plugins / SonarLint-style extensions.** SARIF + LSP export remain for editors that
  consume them, but no first-party IDE plugin is planned.

---

## SonarQube feature comparison (target state)

| Capability | SonarQube (CE / paid) | CodePulse target |
|---|---|---|
| Multi-language analysis | CE limited; many langs paid | **15 langs OSS** (tree-sitter) ✅ |
| Bugs / Vulnerabilities / Code smells | ✅ | ✅ *P1–P2* |
| Security hotspots + review | ✅ | ✅ (done) |
| Metrics (LOC, complexity, duplication) | ✅ | ✅ *P1–P2* |
| Cognitive complexity | ✅ | ✅ *P2* |
| Coverage / test import | ✅ | ✅ *P2* |
| Quality profiles (inherited, custom) | ✅ | ✅ *P2* |
| Quality gates | ✅ | ✅ *P1 basic → P3 new-code* |
| Clean-as-you-code / new-code period | ✅ | ✅ (done) |
| Branch & PR analysis | **paid** | ✅ **OSS** (done) |
| PR decoration (GitHub) | **paid** | ✅ **OSS** (done) |
| Issue tracking across analyses | ✅ | ✅ *P1→P3* |
| External analyzer (SARIF) import | partial | ✅ **first-class** *P2* |
| Rule authoring | Java plugin SDK | **YAML + tree-sitter query** *P1* |
| Rule **coverage** (count/quality) | ✅ thousands, curated | ⚠️ small starter sets — **expanding (P5: JS/TS, Java, Go)** |
| Rule **content** (descriptions, CWE/OWASP, remediation) | ✅ rich | ⚠️ minimal today — **P5** |
| Native semantic / taint dataflow | **paid, deep** | ⚠️ syntactic today; Semgrep/CodeQL via SARIF ✅; **native dataflow P5** |
| Premade CI action (scan + gate) | ✅ scan action | **P5** (`codepulse/scan-action`) |
| SSO (OIDC) | **paid** | ✅ **OSS** (done; presets + GH-Actions keyless P5) |
| Portfolio / aggregation | **paid** | ✅ (done) |
| IDE plugin (SonarLint-style) | ✅ | ❌ out of scope (SARIF/LSP export only) |
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
| **Rule coverage takes years** | Phase 5 expands first-party rules (JS/TS, Java, Go first) with fixture-backed tests; meanwhile external SARIF + native Semgrep interop provide breadth |
| **Issue-tracking instability** (resurrected/duplicated issues) | Content-hash + structural matching, not line numbers; large regression corpus of real diffs |
| **False-positive fatigue** | Every rule ships good/bad fixtures with exact-match assertions; conservative default profiles; easy false-positive marking that sticks |
| **Performance on monorepos** | Parallel scanner, incremental analysis, async ingest queue, table partitioning + retention |
| **Scope creep vs SonarQube's 15-year head start** | Vertical-slice-first; "integrate don't reinvent"; ship each phase independently useful |

---

## Definition of done for v1.0 (public)

- [x] ≥5 languages with default profiles — **15** (…, C++, C#, PHP, Kotlin, Scala, Swift).
- [x] Branch + PR analysis with GitHub decoration.
- [x] Clean-as-you-code gate (new-code period via git blame; `new_*` gate conditions).
- [x] External SARIF consolidation (`-import-sarif`).
- [x] SSO (OIDC) + RBAC (project/user tokens).
- [x] `docker compose up` self-host (server + Postgres); IDE feedback via SARIF + LSP export.
- [x] CodePulse analyzes its own code (dogfooded) and the full suite — incl. a real
  embedded-Postgres integration test — is green.

### Remaining open-ended polish (post-v1.0)
- [x] Scala & Swift added (15 languages). Even more (Go templates, Lua, …) — cheap via `langspec`.
- [in progress] Richer rule sets — debug-leftover rules + security rules (yaml.load/pickle RCE, MD5/SHA-1 weak hash, innerHTML XSS) across languages; ongoing low-FP expansion.
- [investigated] WASM grammars (wazero) to drop CGo — see docs/adr/0001-wasm-grammars.md (deferred post-v1.0; CGo is faster/complete now).
- [x] Dashboard i18n (en/de), light/dark theme, a11y (sr-only/aria), and a **per-file measures drilldown** (sorted by complexity, with coverage).
- [x] Semgrep native interop — `-semgrep <config>` runs the semgrep CLI and ingests its SARIF (tested against a stubbed CLI). Consuming pre-generated SARIF also still works.
