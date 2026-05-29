# CodePulse

> An open-source, self-hostable code quality & security platform — a permissively-licensed alternative to SonarQube.

**Status:** Design phase. No code yet. This repository currently contains the architecture and design documents that define what we're building and in what order.

> ℹ️ **Note:** Before a public launch, verify the "CodePulse" name is clear of trademark conflicts.

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
