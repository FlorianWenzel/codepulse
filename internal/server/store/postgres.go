package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/FlorianWenzel/codepulse/internal/domain"
)

// schema is applied idempotently when a Postgres store is opened.
const schema = `
CREATE TABLE IF NOT EXISTS project (
    key         TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    main_branch TEXT NOT NULL DEFAULT 'main',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE SEQUENCE IF NOT EXISTS analysis_seq;
CREATE TABLE IF NOT EXISTS analysis (
    id          TEXT PRIMARY KEY,
    project_key TEXT NOT NULL REFERENCES project(key),
    branch      TEXT NOT NULL DEFAULT 'main',
    created_at  TIMESTAMPTZ NOT NULL,
    summary     JSONB NOT NULL,
    metrics     JSONB NOT NULL,
    gate        JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS analysis_project_branch_created ON analysis(project_key, branch, created_at DESC);
CREATE TABLE IF NOT EXISTS issue (
    project_key       TEXT NOT NULL REFERENCES project(key),
    branch            TEXT NOT NULL DEFAULT 'main',
    key               TEXT NOT NULL,
    rule_id           TEXT NOT NULL,
    type              TEXT NOT NULL,
    severity          TEXT NOT NULL,
    message           TEXT NOT NULL,
    file              TEXT NOT NULL,
    line              INT  NOT NULL,
    status            TEXT NOT NULL,
    resolution        TEXT NOT NULL DEFAULT '',
    assignee          TEXT NOT NULL DEFAULT '',
    comments          JSONB NOT NULL DEFAULT '[]',
    first_analysis_id TEXT NOT NULL,
    last_analysis_id  TEXT NOT NULL,
    PRIMARY KEY (project_key, branch, key)
);
CREATE TABLE IF NOT EXISTS token (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    role        TEXT NOT NULL,
    project_key TEXT NOT NULL DEFAULT '',
    hash        TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS hotspot (
    project_key      TEXT NOT NULL REFERENCES project(key),
    branch           TEXT NOT NULL DEFAULT 'main',
    key              TEXT NOT NULL,
    rule_id          TEXT NOT NULL,
    message          TEXT NOT NULL,
    file             TEXT NOT NULL,
    line             INT  NOT NULL,
    status           TEXT NOT NULL,
    resolution       TEXT NOT NULL DEFAULT '',
    last_analysis_id TEXT NOT NULL,
    PRIMARY KEY (project_key, branch, key)
);
`

// Postgres is a Store backed by PostgreSQL.
type Postgres struct {
	pool *pgxpool.Pool
}

// OpenPostgres connects to dsn and applies the schema.
func OpenPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

// Close releases the connection pool.
func (p *Postgres) Close() { p.pool.Close() }

func branchOr(b string) string {
	if b == "" {
		return "main"
	}
	return b
}

func (p *Postgres) CreateProject(pr Project) error {
	if pr.Key == "" {
		return fmt.Errorf("project key required")
	}
	if pr.MainBranch == "" {
		pr.MainBranch = "main"
	}
	ct, err := p.pool.Exec(context.Background(),
		`INSERT INTO project(key, name, main_branch, created_at) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
		pr.Key, pr.Name, pr.MainBranch, pr.CreatedAt)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("project %q already exists", pr.Key)
	}
	return nil
}

func (p *Postgres) GetProject(key string) (Project, bool) {
	var pr Project
	err := p.pool.QueryRow(context.Background(),
		`SELECT key, name, main_branch, created_at FROM project WHERE key=$1`, key).
		Scan(&pr.Key, &pr.Name, &pr.MainBranch, &pr.CreatedAt)
	if err != nil {
		return Project{}, false
	}
	return pr, true
}

func (p *Postgres) ListProjects() []Project {
	rows, err := p.pool.Query(context.Background(),
		`SELECT key, name, main_branch, created_at FROM project ORDER BY key`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		var pr Project
		if err := rows.Scan(&pr.Key, &pr.Name, &pr.MainBranch, &pr.CreatedAt); err == nil {
			out = append(out, pr)
		}
	}
	return out
}

func (p *Postgres) SaveAnalysis(a Analysis, findings []domain.Finding) (Analysis, error) {
	a.Branch = branchOr(a.Branch)
	ctx := context.Background()
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return Analysis{}, err
	}
	defer tx.Rollback(ctx)

	if err := tx.QueryRow(ctx, `SELECT 'a' || nextval('analysis_seq')`).Scan(&a.ID); err != nil {
		return Analysis{}, err
	}

	summaryJSON, _ := json.Marshal(a.Summary)
	metricsJSON, _ := json.Marshal(a.Metrics)
	gateJSON, _ := json.Marshal(a.Gate)
	if _, err := tx.Exec(ctx,
		`INSERT INTO analysis(id, project_key, branch, created_at, summary, metrics, gate) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		a.ID, a.ProjectKey, a.Branch, a.CreatedAt, summaryJSON, metricsJSON, gateJSON); err != nil {
		return Analysis{}, err
	}

	seenIssues := make([]string, 0, len(findings))
	for _, f := range findings {
		k := findingKey(f)
		if f.Type == domain.TypeHotspot {
			if _, err := tx.Exec(ctx, `
INSERT INTO hotspot(project_key, branch, key, rule_id, message, file, line, status, resolution, last_analysis_id)
VALUES ($1,$2,$3,$4,$5,$6,$7,'TO_REVIEW','',$8)
ON CONFLICT (project_key, branch, key) DO UPDATE SET last_analysis_id=excluded.last_analysis_id, line=excluded.line`,
				a.ProjectKey, a.Branch, k, f.RuleID, f.Message, f.Location.File, f.Location.StartLine, a.ID); err != nil {
				return Analysis{}, err
			}
			continue
		}

		seenIssues = append(seenIssues, k)
		if _, err := tx.Exec(ctx, `
INSERT INTO issue(project_key, branch, key, rule_id, type, severity, message, file, line, status, resolution, first_analysis_id, last_analysis_id)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'OPEN','',$10,$10)
ON CONFLICT (project_key, branch, key) DO UPDATE SET
    last_analysis_id = excluded.last_analysis_id,
    line             = excluded.line,
    severity         = excluded.severity,
    status           = CASE WHEN issue.status='CLOSED' AND issue.resolution='FIXED' THEN 'REOPENED' ELSE issue.status END,
    resolution       = CASE WHEN issue.status='CLOSED' AND issue.resolution='FIXED' THEN ''         ELSE issue.resolution END`,
			a.ProjectKey, a.Branch, k, f.RuleID, string(f.Type), string(f.Severity), f.Message,
			f.Location.File, f.Location.StartLine, a.ID); err != nil {
			return Analysis{}, err
		}
	}

	if _, err := tx.Exec(ctx, `
UPDATE issue SET status='CLOSED', resolution='FIXED', last_analysis_id=$3
WHERE project_key=$1 AND branch=$2 AND status IN ('OPEN','CONFIRMED','REOPENED') AND key <> ALL($4)`,
		a.ProjectKey, a.Branch, a.ID, seenIssues); err != nil {
		return Analysis{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Analysis{}, err
	}
	return a, nil
}

func (p *Postgres) LatestAnalysis(projectKey, branch string) (Analysis, bool) {
	var a Analysis
	var summaryJSON, metricsJSON, gateJSON []byte
	err := p.pool.QueryRow(context.Background(), `
SELECT id, project_key, branch, created_at, summary, metrics, gate
FROM analysis WHERE project_key=$1 AND branch=$2 ORDER BY created_at DESC, id DESC LIMIT 1`,
		projectKey, branchOr(branch)).
		Scan(&a.ID, &a.ProjectKey, &a.Branch, &a.CreatedAt, &summaryJSON, &metricsJSON, &gateJSON)
	if err != nil {
		return Analysis{}, false
	}
	_ = json.Unmarshal(summaryJSON, &a.Summary)
	_ = json.Unmarshal(metricsJSON, &a.Metrics)
	_ = json.Unmarshal(gateJSON, &a.Gate)
	return a, true
}

const issueCols = `project_key, branch, key, rule_id, type, severity, message, file, line, status, resolution, assignee, comments, first_analysis_id, last_analysis_id`

func scanIssue(row pgx.Row) (Issue, error) {
	var is Issue
	var typ, sev, branch string
	var commentsJSON []byte
	_ = branch
	if err := row.Scan(&is.ProjectKey, &branch, &is.Key, &is.RuleID, &typ, &sev, &is.Message,
		&is.File, &is.Line, &is.Status, &is.Resolution, &is.Assignee, &commentsJSON,
		&is.FirstAnalysisID, &is.LastAnalysisID); err != nil {
		return Issue{}, err
	}
	is.Type = domain.IssueType(typ)
	is.Severity = domain.Severity(sev)
	_ = json.Unmarshal(commentsJSON, &is.Comments)
	return is, nil
}

func (p *Postgres) Issues(projectKey, branch string, openOnly bool) []Issue {
	q := `SELECT ` + issueCols + ` FROM issue WHERE project_key=$1 AND branch=$2`
	if openOnly {
		q += ` AND status IN ('OPEN','CONFIRMED','REOPENED')`
	}
	q += ` ORDER BY file, line, rule_id`
	rows, err := p.pool.Query(context.Background(), q, projectKey, branchOr(branch))
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Issue
	for rows.Next() {
		if is, err := scanIssue(rows); err == nil {
			out = append(out, is)
		}
	}
	return out
}

func (p *Postgres) NewIssues(projectKey, branch, base string) []Issue {
	q := `SELECT ` + issueCols + ` FROM issue
WHERE project_key=$1 AND branch=$2 AND status IN ('OPEN','CONFIRMED','REOPENED')
AND key NOT IN (SELECT key FROM issue WHERE project_key=$1 AND branch=$3)
ORDER BY file, line, rule_id`
	rows, err := p.pool.Query(context.Background(), q, projectKey, branchOr(branch), branchOr(base))
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Issue
	for rows.Next() {
		if is, err := scanIssue(rows); err == nil {
			out = append(out, is)
		}
	}
	return out
}

func (p *Postgres) getIssue(projectKey, branch, key string) (Issue, error) {
	row := p.pool.QueryRow(context.Background(),
		`SELECT `+issueCols+` FROM issue WHERE project_key=$1 AND branch=$2 AND key=$3`,
		projectKey, branchOr(branch), key)
	is, err := scanIssue(row)
	if err != nil {
		return Issue{}, fmt.Errorf("issue not found")
	}
	return is, nil
}

func (p *Postgres) TransitionIssue(projectKey, branch, key, transition string) (Issue, error) {
	is, err := p.getIssue(projectKey, branch, key)
	if err != nil {
		return Issue{}, err
	}
	if err := applyTransition(&is, transition); err != nil {
		return Issue{}, err
	}
	_, err = p.pool.Exec(context.Background(),
		`UPDATE issue SET status=$4, resolution=$5 WHERE project_key=$1 AND branch=$2 AND key=$3`,
		projectKey, branchOr(branch), key, is.Status, is.Resolution)
	return is, err
}

func (p *Postgres) AssignIssue(projectKey, branch, key, assignee string) (Issue, error) {
	ct, err := p.pool.Exec(context.Background(),
		`UPDATE issue SET assignee=$4 WHERE project_key=$1 AND branch=$2 AND key=$3`,
		projectKey, branchOr(branch), key, assignee)
	if err != nil {
		return Issue{}, err
	}
	if ct.RowsAffected() == 0 {
		return Issue{}, fmt.Errorf("issue not found")
	}
	return p.getIssue(projectKey, branch, key)
}

func (p *Postgres) CommentIssue(projectKey, branch, key, author, text string, at time.Time) (Issue, error) {
	is, err := p.getIssue(projectKey, branch, key)
	if err != nil {
		return Issue{}, err
	}
	is.Comments = append(is.Comments, Comment{Author: author, Text: text, At: at})
	cj, _ := json.Marshal(is.Comments)
	_, err = p.pool.Exec(context.Background(),
		`UPDATE issue SET comments=$4 WHERE project_key=$1 AND branch=$2 AND key=$3`,
		projectKey, branchOr(branch), key, cj)
	return is, err
}

func (p *Postgres) Hotspots(projectKey, branch, status string) []Hotspot {
	q := `SELECT project_key, key, rule_id, message, file, line, status, resolution, last_analysis_id
          FROM hotspot WHERE project_key=$1 AND branch=$2`
	args := []any{projectKey, branchOr(branch)}
	if status != "" {
		q += ` AND status=$3`
		args = append(args, status)
	}
	q += ` ORDER BY file, line`
	rows, err := p.pool.Query(context.Background(), q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Hotspot
	for rows.Next() {
		var h Hotspot
		if err := rows.Scan(&h.ProjectKey, &h.Key, &h.RuleID, &h.Message, &h.File, &h.Line,
			&h.Status, &h.Resolution, &h.LastAnalysisID); err == nil {
			out = append(out, h)
		}
	}
	return out
}

func (p *Postgres) ResolveHotspot(projectKey, branch, key, resolution string) (Hotspot, error) {
	if !validHotspotResolution(resolution) {
		return Hotspot{}, fmt.Errorf("invalid hotspot resolution %q", resolution)
	}
	ct, err := p.pool.Exec(context.Background(),
		`UPDATE hotspot SET status='REVIEWED', resolution=$4 WHERE project_key=$1 AND branch=$2 AND key=$3`,
		projectKey, branchOr(branch), key, resolution)
	if err != nil {
		return Hotspot{}, err
	}
	if ct.RowsAffected() == 0 {
		return Hotspot{}, fmt.Errorf("hotspot not found")
	}
	var h Hotspot
	err = p.pool.QueryRow(context.Background(), `
SELECT project_key, key, rule_id, message, file, line, status, resolution, last_analysis_id
FROM hotspot WHERE project_key=$1 AND branch=$2 AND key=$3`, projectKey, branchOr(branch), key).
		Scan(&h.ProjectKey, &h.Key, &h.RuleID, &h.Message, &h.File, &h.Line, &h.Status, &h.Resolution, &h.LastAnalysisID)
	return h, err
}

func (p *Postgres) CreateToken(t Token) error {
	if t.Hash == "" {
		return fmt.Errorf("token hash required")
	}
	_, err := p.pool.Exec(context.Background(),
		`INSERT INTO token(id, name, role, project_key, hash, created_at) VALUES ($1,$2,$3,$4,$5,$6)`,
		t.ID, t.Name, t.Role, t.ProjectKey, t.Hash, t.CreatedAt)
	return err
}

func (p *Postgres) AuthToken(hash string) (Token, bool) {
	var t Token
	err := p.pool.QueryRow(context.Background(),
		`SELECT id, name, role, project_key, hash, created_at FROM token WHERE hash=$1`, hash).
		Scan(&t.ID, &t.Name, &t.Role, &t.ProjectKey, &t.Hash, &t.CreatedAt)
	if err != nil {
		return Token{}, false
	}
	return t, true
}

func (p *Postgres) PruneAnalyses(projectKey, branch string, keep int) (int, error) {
	if keep < 0 {
		keep = 0
	}
	ct, err := p.pool.Exec(context.Background(), `
DELETE FROM analysis WHERE project_key=$1 AND branch=$2 AND id NOT IN (
    SELECT id FROM analysis WHERE project_key=$1 AND branch=$2 ORDER BY created_at DESC, id DESC LIMIT $3)`,
		projectKey, branchOr(branch), keep)
	if err != nil {
		return 0, err
	}
	return int(ct.RowsAffected()), nil
}

// compile-time checks that both stores satisfy the interface.
var (
	_ Store = (*Memory)(nil)
	_ Store = (*Postgres)(nil)
)
