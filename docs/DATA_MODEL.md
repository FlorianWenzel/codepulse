# CodePulse — Data Model

PostgreSQL schema, the issue/measure model, and the algorithm that tracks issues
across analyses (the part that's easy to get wrong and is core to the product).

---

## 1. Core entities

```
organization 1──* project 1──* analysis 1──* issue_occurrence
                     │              │
                     │              └──* measure
                     │
                     ├──* branch / pull_request
                     ├── quality_profile (per language)  *──* rule
                     └── quality_gate *──* gate_condition

issue (logical, long-lived) 1──* issue_occurrence (per analysis)
rule *──1 repository(rule namespace)        user, group, permission, token
```

Key distinction:
- **`issue`** = a *logical* problem that persists across analyses (it can be open for weeks, get assigned, marked won't-fix, then fixed). Has a stable id.
- **`issue_occurrence`** = the appearance of that issue in one specific analysis (exact line, snippet, hash). Issue tracking links occurrences to the same logical `issue`.

This separation is what lets the dashboard say "this issue has been open 14 days, assigned to X, first seen in analysis #42" rather than treating every scan as brand-new.

---

## 2. Schema (illustrative DDL)

```sql
-- ── Tenancy & projects ───────────────────────────────────────────────
CREATE TABLE organization (
  id            UUID PRIMARY KEY,
  key           TEXT UNIQUE NOT NULL,
  name          TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE project (
  id              UUID PRIMARY KEY,
  org_id          UUID NOT NULL REFERENCES organization(id),
  key             TEXT NOT NULL,                 -- e.g. "acme:billing-svc"
  name            TEXT NOT NULL,
  main_branch     TEXT NOT NULL DEFAULT 'main',
  quality_gate_id UUID REFERENCES quality_gate(id),
  new_code_def    JSONB NOT NULL,                -- {type: previous_version|days|date|ref_branch, value:…}
  visibility      TEXT NOT NULL DEFAULT 'private',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, key)
);

CREATE TABLE branch (
  id          UUID PRIMARY KEY,
  project_id  UUID NOT NULL REFERENCES project(id),
  name        TEXT NOT NULL,
  kind        TEXT NOT NULL,        -- 'branch' | 'pull_request'
  is_main     BOOLEAN NOT NULL DEFAULT false,
  pr_number   INT,                  -- when kind='pull_request'
  base_branch TEXT,
  UNIQUE (project_id, name)
);

-- ── Analyses (immutable snapshots) ──────────────────────────────────
CREATE TABLE analysis (
  id              UUID PRIMARY KEY,
  project_id      UUID NOT NULL REFERENCES project(id),
  branch_id       UUID NOT NULL REFERENCES branch(id),
  commit_sha      TEXT,
  scanner_version TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  gate_status     TEXT,             -- 'OK' | 'ERROR' | 'NONE' (set after eval)
  new_code_base   TEXT,             -- commit/date marking the new-code baseline
  meta            JSONB             -- language stats, durations, file count…
);
CREATE INDEX ON analysis (project_id, branch_id, created_at DESC);

-- ── Rules & profiles ────────────────────────────────────────────────
CREATE TABLE rule (
  id            TEXT PRIMARY KEY,          -- "go:S1234" / "python:unused-import"
  repository    TEXT NOT NULL,             -- "codepulse-go", "external-eslint", …
  language      TEXT NOT NULL,
  name          TEXT NOT NULL,
  type          TEXT NOT NULL,             -- 'BUG'|'VULNERABILITY'|'CODE_SMELL'|'HOTSPOT'
  default_sev   TEXT NOT NULL,             -- 'BLOCKER'|'CRITICAL'|'MAJOR'|'MINOR'|'INFO'
  remediation_min INT,                     -- base remediation effort (minutes)
  cwe           TEXT[],                    -- security taxonomy refs
  owasp         TEXT[],
  description_md TEXT NOT NULL,
  tags          TEXT[]
);

CREATE TABLE quality_profile (
  id        UUID PRIMARY KEY,
  org_id    UUID NOT NULL REFERENCES organization(id),
  language  TEXT NOT NULL,
  name      TEXT NOT NULL,
  is_default BOOLEAN NOT NULL DEFAULT false,
  parent_id UUID REFERENCES quality_profile(id),   -- inheritance
  UNIQUE (org_id, language, name)
);

CREATE TABLE profile_rule (          -- which rules are active in a profile
  profile_id UUID REFERENCES quality_profile(id),
  rule_id    TEXT REFERENCES rule(id),
  severity   TEXT NOT NULL,          -- overrides rule.default_sev
  params     JSONB,                  -- rule parameters (thresholds, etc.)
  PRIMARY KEY (profile_id, rule_id)
);

CREATE TABLE project_profile (       -- project ↔ active profile per language
  project_id UUID REFERENCES project(id),
  language   TEXT NOT NULL,
  profile_id UUID REFERENCES quality_profile(id),
  PRIMARY KEY (project_id, language)
);

-- ── Quality gates ───────────────────────────────────────────────────
CREATE TABLE quality_gate (
  id         UUID PRIMARY KEY,
  org_id     UUID NOT NULL REFERENCES organization(id),
  name       TEXT NOT NULL,
  is_default BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE gate_condition (
  id        UUID PRIMARY KEY,
  gate_id   UUID NOT NULL REFERENCES quality_gate(id),
  metric    TEXT NOT NULL,           -- 'new_coverage', 'new_blocker_issues', …
  op        TEXT NOT NULL,           -- 'LT'|'GT'|'EQ'|'NE'|'WORSE_THAN'
  threshold TEXT NOT NULL,
  on_new_code BOOLEAN NOT NULL DEFAULT true
);

-- ── Issues (logical) & occurrences (per analysis) ───────────────────
CREATE TABLE issue (
  id            UUID PRIMARY KEY,
  project_id    UUID NOT NULL REFERENCES project(id),
  branch_id     UUID NOT NULL REFERENCES branch(id),
  rule_id       TEXT NOT NULL REFERENCES rule(id),
  type          TEXT NOT NULL,
  severity      TEXT NOT NULL,
  status        TEXT NOT NULL,       -- 'OPEN'|'CONFIRMED'|'REOPENED'|'RESOLVED'|'CLOSED'
  resolution    TEXT,                -- NULL|'FIXED'|'FALSE_POSITIVE'|'WONT_FIX'
  message       TEXT NOT NULL,
  component_path TEXT NOT NULL,      -- file path (relative to project root)
  effort_min    INT,
  assignee_id   UUID REFERENCES app_user(id),
  author        TEXT,                -- SCM author who introduced it (blame)
  introduced_at TIMESTAMPTZ,        -- commit date of introducing line
  is_new_code   BOOLEAN NOT NULL DEFAULT false,
  first_analysis_id UUID REFERENCES analysis(id),
  last_analysis_id  UUID REFERENCES analysis(id),
  line_hash     TEXT NOT NULL,       -- for tracking (see §4)
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON issue (project_id, branch_id, status);
CREATE INDEX ON issue (project_id, rule_id);
CREATE INDEX ON issue (assignee_id) WHERE status IN ('OPEN','CONFIRMED','REOPENED');

CREATE TABLE issue_occurrence (
  id           UUID PRIMARY KEY,
  issue_id     UUID NOT NULL REFERENCES issue(id),
  analysis_id  UUID NOT NULL REFERENCES analysis(id),
  start_line   INT, start_col INT, end_line INT, end_col INT,
  locations    JSONB,               -- secondary/flow locations
  code_snippet TEXT,
  PRIMARY KEY (id)
);
CREATE INDEX ON issue_occurrence (analysis_id);
CREATE INDEX ON issue_occurrence (issue_id);

CREATE TABLE issue_change (          -- changelog: transitions, assignments, comments
  id         UUID PRIMARY KEY,
  issue_id   UUID NOT NULL REFERENCES issue(id),
  user_id    UUID REFERENCES app_user(id),
  kind       TEXT NOT NULL,         -- 'transition'|'assign'|'comment'|'severity'
  detail     JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Measures (metrics) ──────────────────────────────────────────────
CREATE TABLE metric (
  key         TEXT PRIMARY KEY,      -- 'ncloc','complexity','coverage','duplicated_lines_density',…
  name        TEXT NOT NULL,
  value_type  TEXT NOT NULL,         -- 'INT'|'FLOAT'|'PERCENT'|'RATING'|'LEVEL'
  domain      TEXT NOT NULL,         -- 'Size'|'Complexity'|'Coverage'|'Reliability'|…
  direction   INT NOT NULL,          -- 1 = higher is better, -1 = lower is better, 0 = none
  is_new_code BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE measure (
  analysis_id  UUID NOT NULL REFERENCES analysis(id),
  component_path TEXT NOT NULL,      -- '' = project root; else dir/file path
  metric_key   TEXT NOT NULL REFERENCES metric(key),
  value_num    DOUBLE PRECISION,
  value_text   TEXT,                 -- for RATING/LEVEL
  PRIMARY KEY (analysis_id, component_path, metric_key)
);
CREATE INDEX ON measure (analysis_id, metric_key);

-- ── Security hotspots ───────────────────────────────────────────────
CREATE TABLE hotspot (
  id          UUID PRIMARY KEY,
  project_id  UUID NOT NULL REFERENCES project(id),
  branch_id   UUID NOT NULL REFERENCES branch(id),
  rule_id     TEXT NOT NULL REFERENCES rule(id),
  component_path TEXT NOT NULL,
  line        INT,
  status      TEXT NOT NULL,         -- 'TO_REVIEW'|'REVIEWED'
  resolution  TEXT,                  -- NULL|'SAFE'|'FIXED'|'ACKNOWLEDGED'
  category    TEXT,                  -- OWASP category
  line_hash   TEXT NOT NULL,
  assignee_id UUID REFERENCES app_user(id)
);

-- ── Identity & access ───────────────────────────────────────────────
CREATE TABLE app_user (
  id         UUID PRIMARY KEY,
  login      TEXT UNIQUE NOT NULL,
  email      TEXT,
  name       TEXT,
  is_active  BOOLEAN NOT NULL DEFAULT true,
  external_provider TEXT,           -- 'local'|'github'|'oidc'
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE token (
  id          UUID PRIMARY KEY,
  name        TEXT NOT NULL,
  kind        TEXT NOT NULL,         -- 'project_analysis'|'user_pat'
  project_id  UUID REFERENCES project(id),
  user_id     UUID REFERENCES app_user(id),
  hash        TEXT NOT NULL,         -- argon2/sha256 of the token; never store plaintext
  last_used_at TIMESTAMPTZ,
  expires_at  TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE permission (            -- RBAC: subject → role on scope
  id        UUID PRIMARY KEY,
  subject_kind TEXT NOT NULL,        -- 'user'|'group'
  subject_id   UUID NOT NULL,
  scope_kind   TEXT NOT NULL,        -- 'global'|'project'
  scope_id     UUID,                 -- project id when project-scoped
  role         TEXT NOT NULL         -- 'admin'|'maintainer'|'scan'|'viewer'
);

-- ── Durable job queue (ingest) ──────────────────────────────────────
CREATE TABLE ingest_job (
  id          UUID PRIMARY KEY,
  project_id  UUID NOT NULL,
  payload_ref TEXT NOT NULL,         -- storage location of the raw report
  status      TEXT NOT NULL,         -- 'queued'|'running'|'done'|'failed'
  attempts    INT NOT NULL DEFAULT 0,
  error       TEXT,
  locked_at   TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- workers: SELECT … FOR UPDATE SKIP LOCKED to claim jobs.
```

---

## 3. Measures: aggregation & ratings

- Scanner emits **file-level** measures. The worker **rolls them up** to directories and project root (sums for additive metrics like `ncloc`/`complexity`; weighted averages or recomputation for densities/percentages).
- **Coverage** is stored per file (lines-to-cover, covered-lines, conditions, etc.) and aggregated.
- **Ratings (A–E)** are derived, not stored raw, from primitive measures:
  - *Reliability rating* ← worst open BUG severity present.
  - *Security rating* ← worst open VULNERABILITY severity.
  - *Maintainability rating* ← technical-debt ratio = remediation effort ÷ estimated dev cost of the code (LOC × per-line cost).
- `new_*` variants are computed by restricting to lines/issues within the new-code period (§5 of ARCHITECTURE).

---

## 4. Issue tracking across analyses (the hard part)

Goal: when analysis N+1 arrives, decide for each newly-reported finding whether it is the **same logical issue** as an existing open one (carry over status/assignee/age) or **genuinely new**, and which previously-open issues are now **fixed** (close them).

This must survive line-number drift (code shifted up/down), reformatting, and small edits — otherwise every refactor resurrects "resolved" issues and the new-code gate becomes useless.

**Algorithm (per project+branch, on each analysis):**

1. **Candidate set:** all currently open/confirmed issues for the rule+file from the *previous* analysis (the "base"), and all findings reported in the *new* analysis for that rule+file.

2. **Match in priority order** (first match wins, each base issue matched at most once):
   1. **Same line hash + same rule** — `line_hash` = hash of the *trimmed, normalized* text of the issue's primary line(s). Robust to line-number shifts.
   2. **Same message + same enclosing function/block** — uses the structural path (e.g. `pkg/foo.go::Bar`) so a moved function keeps its issue.
   3. **Same rule + nearest line within a small window**, tie-broken by snippet similarity (token-level), for cases where the line changed slightly.
   3 fall through to: treat as **new** issue.

3. **Outcome:**
   - Matched → reuse the logical `issue`, append an `issue_occurrence`, update `last_analysis_id`, keep `status`/`resolution`/`assignee`. If it was `RESOLVED(FIXED)` but reappears → **reopen** (`REOPENED`) and log a change.
   - Unmatched new finding → create a new `issue` (`status=OPEN`, `is_new_code` set from blame), first occurrence.
   - Base issue with no match in the new analysis → it's **fixed**: set `status=CLOSED`, `resolution=FIXED`, log change. (Unless the whole file was excluded/unanalyzed this run — then leave untouched.)

4. **Manual resolutions are sticky:** `FALSE_POSITIVE` / `WONT_FIX` carry across as long as the finding keeps matching; they don't get reopened by re-detection.

**Why line hashing over line numbers:** SonarQube learned this the hard way; matching by content hash + structural context is what makes issue history stable. We store `line_hash` on both `issue` and at compute-time on findings to make step 2.1 an indexed lookup.

**PR / branch issues:** for a pull-request branch, the base is the **target branch's** latest analysis, so the PR shows only issues *introduced by the PR* ("new issues on this PR") — the basis for PR gate decoration.

---

## 5. Retention & performance

- `issue_occurrence`, `measure`, and `analysis` rows grow fast. Strategy:
  - Keep **full** occurrences/measures for the **last K analyses** + all analyses tagged as "version events"; **prune** intermediate ones (configurable retention).
  - Logical `issue` rows are never deleted while open; closed issues older than retention are purged.
  - File-level measures for historical analyses can be down-sampled to project/dir level after retention window.
- Partition `measure` and `issue_occurrence` by `analysis_id` range (or by month) on large installs.
- Heavy dashboard reads hit only the **latest** analysis per branch (denormalized "current" pointers on `project`/`branch` for O(1) lookup).

---

## 6. Multitenancy & visibility

- Everything is scoped under `organization`; a single-org install just has one.
- Project `visibility` (`public`/`private`) + RBAC via `permission` rows gate every read.
- Analysis tokens are project-scoped and can only ingest, never read other projects.
