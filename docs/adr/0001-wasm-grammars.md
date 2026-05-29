# ADR 0001 — Tree-sitter bindings: CGo now, WASM (wazero) later

**Status:** Accepted (investigation complete) · **Date:** 2026-05

## Context

CodePulse parses source with tree-sitter. Two ways to embed the grammars in a Go binary:

1. **CGo** via `github.com/smacker/go-tree-sitter` — the C runtime + each grammar's
   generated C are compiled into the binary. This is what we use today (13 languages).
2. **WASM** — compile each grammar to `tree-sitter`'s WASM target and run it through a
   pure-Go runtime such as [`wazero`](https://wazero.io/), giving a **CGo-free** build.

## Findings

- **CGo (current):** works well and is fast. Cost: builds require a C toolchain, and
  cross-compilation needs per-target setup (we ship a per-platform release matrix). The
  whole test suite — including a real embedded-Postgres integration test — is green, and
  the scanner self-scans 13 languages in CI on `ubuntu-latest` (gcc preinstalled).
- **WASM (wazero):** removes the C toolchain dependency and makes cross-compilation
  trivial (one pure-Go binary per OS/arch). Trade-offs measured/expected:
  - Parsing throughput is lower than native C (WASM interpretation/JIT overhead).
  - tree-sitter's own WASM support and the Go host bindings are less mature than the C
    path; per-grammar `.wasm` artifacts must be built and version-pinned (same drift risk
    as today, different packaging).
  - The `Query`/`QueryCursor` API surface we rely on must be available through the WASM
    host bindings.

## Decision

Stay on **CGo for v1.0** — it is faster, complete, and already shipping. Treat WASM as a
**post-v1.0 build-simplification track**, not a feature change: the `langspec` + `parse`
abstractions already isolate grammar access, so swapping the backend is localized.

## Migration sketch (when we pursue it)

1. Add a `parse` backend interface; keep CGo as the default implementation.
2. Add a `wazero`-based implementation loading pinned per-grammar `.wasm` modules.
3. Gate behind a build tag; run the **existing rule corpus** (exact-match fixtures for all
   languages) against both backends in CI to guarantee identical findings.
4. Benchmark; if throughput is acceptable, make WASM the default for release binaries and
   drop the per-platform CGo matrix.

## Consequences

- No code change now; this records the evaluation so the choice is deliberate.
- The rule/metric tests are backend-agnostic, so they double as the WASM acceptance suite.
