# CodePulse

> An open-source, self-hostable code quality & security platform — a permissively-licensed alternative to SonarQube.

**Status:** Phases 1–4 implemented and end-to-end tested. Working today:

- **Scanner** (`codepulse-scan`): 7 languages via tree-sitter (**Go, Python, JavaScript, TypeScript, Java, Ruby, Rust**); rules for bugs/vulnerabilities/code-smells/security-hotspots; metrics (LOC, cyclomatic & cognitive complexity, comments), **duplication detection**, **coverage import** (LCOV/Go/Cobertura), A–E **ratings** + technical debt, **new-code period** via git blame; SARIF 2.1.0 + JSON output; **external-analyzer SARIF import** (consolidate gosec/ESLint/Bandit/…).
- **Server** (`codepulse-server`): HTTP API over an in-memory or **PostgreSQL** store; analysis ingest with cross-analysis **issue tracking**, **quality gates** (incl. clean-as-you-code), **branch/PR analysis** (new-vs-base), **GitHub PR decoration**, **security-hotspot & issue triage workflows**, **portfolio aggregation**, **retention/pruning**, **notifications webhook**, **token auth + RBAC**, and **OIDC SSO**.
- **Dashboard** (`web/`): Vue 3 SPA — projects, gate/ratings/measures, issues browser.

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full status + SonarQube comparison.

```sh
# Scanner
make build                                   # build bin/codepulse-scan + bin/codepulse-server
./bin/codepulse-scan ./path                  # scan (JSON to stdout, summary to stderr)
./bin/codepulse-scan -format sarif -o out.sarif ./path
./bin/codepulse-scan -coverage cover.out -new-code-days 30 -import-sarif gosec.sarif ./path
make test                                    # unit + e2e tests (incl. a real embedded Postgres)

# Server (self-host)
docker compose -f deploy/docker-compose.yml up --build   # server + Postgres
# or: DATABASE_URL=... CODEPULSE_ADMIN_TOKEN=... ./bin/codepulse-server

# Dashboard
cd web && npm install && npm run dev         # proxies /api to :8080
```

> ℹ️ **Note:** Before a public launch, verify the "CodePulse" name is clear of trademark conflicts.

## GitHub Action

Run the analysis and **fail the build on the quality gate** in one step (like `sonarqube-scan-action`):

```yaml
# .github/workflows/codepulse.yml
- uses: FlorianWenzel/codepulse@v1
  with:
    path: .
    # Local gate (no server): fail on findings at/above this severity
    fail-on: CRITICAL
    # — or — server mode: upload and enforce the project's quality gate
    # server-url: https://codepulse.example.com
    # token: ${{ secrets.CODEPULSE_TOKEN }}
    # project: my-project
    # base: ${{ github.base_ref }}   # PR: only new-vs-base issues
```

In server mode the step uploads the report (branch/PR-aware) and exits non-zero if the
gate is `ERROR`. The same logic is in [`deploy/ci/gate.sh`](deploy/ci/gate.sh) for other CI.

---

## What is this?

CodePulse scans your source code for **bugs**, **security vulnerabilities**, and **maintainability problems** ("code smells"), tracks quality **metrics** over time, and enforces **quality gates** in CI — across many programming languages. It is designed to be:

- **Multi-language by default** — built on [tree-sitter](https://tree-sitter.github.io/), so adding a language is mostly grammar + rules, not a new analyzer.
- **Self-hostable & permissive** — Apache-2.0, no "Community Edition crippling," no per-language paywall.
- **CI-native** — a single static Go binary scanner; results upload to a server or emit SARIF locally.
- **Fast** — Go scanner, incremental analysis, parallel file processing.

## Why another one?

SonarQube is excellent but: the open-source Community Edition gates many languages and features behind paid tiers, it's a heavyweight JVM deployment, and rule authoring is Java-plugin-heavy. Existing OSS point tools (Semgrep, CodeQL, ESLint, etc.) each cover slices. CodePulse aims to be the **integrated dashboard + multi-language engine + quality gate** layer, fully open.

## High-level shape

```
  Developer / CI                    CodePulse Server                  Browser
 ┌──────────────┐   scan results   ┌──────────────┐   REST/JSON   ┌──────────┐
 │ codepulse-scan   │ ───────────────► │  Go API      │ ◄──────────── │ Vue SPA  │
 │ (Go CLI)     │   (SARIF-like)   │  + workers   │               │ dashboard│
 │  tree-sitter │                  │  PostgreSQL  │               └──────────┘
 └──────────────┘                  └──────────────┘
```

## Documents

| Doc | What's in it |
|-----|--------------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System components, scanner pipeline, tree-sitter integration, API surface, deployment |
| [docs/DATA_MODEL.md](docs/DATA_MODEL.md) | PostgreSQL schema, issue/measure model, issue-tracking-across-analyses algorithm |
| [docs/RULES.md](docs/RULES.md) | Rule engine, rule authoring format (YAML + tree-sitter queries), quality profiles |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Phased milestones from MVP to feature parity, with a SonarQube comparison matrix |

## Tech stack (decided)

- **Scanner & server:** Go
- **Parsing:** tree-sitter (via `go-tree-sitter` CGo bindings)
- **Dashboard:** Vue 3 (Composition API) + Vite
- **Storage:** PostgreSQL
- **Output interchange:** SARIF 2.1.0 (plus an internal richer JSON)
- **License:** Apache-2.0

## Quick mental model

1. `codepulse-scan` walks a project, parses each file into a tree-sitter AST.
2. **Rules** (tree-sitter queries + small Go/DSL predicates) flag **issues**.
3. **Metrics** (LOC, complexity, duplication, coverage) are computed per file/dir/project.
4. Results upload to the **server**, which stores a new **analysis** snapshot, tracks issues across runs, and evaluates the project's **quality gate**.
5. The **Vue dashboard** shows projects, the issue browser, trends, and pass/fail gate status.
