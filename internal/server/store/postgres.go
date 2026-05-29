package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/FlorianWenzel/codepulse/internal/domain"
)

// schema is applied idempotently when a Postgres store is opened.
const schema = `
CREATE TABLE IF NOT EXISTS project (
    key        TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE SEQUENCE IF NOT EXISTS analysis_seq;
CREATE TABLE IF NOT EXISTS analysis (
    id          TEXT PRIMARY KEY,
    project_key TEXT NOT NULL REFERENCES project(key),
    created_at  TIMESTAMPTZ NOT NULL,
    summary     JSONB NOT NULL,
    metrics     JSONB NOT NULL,
    gate        JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS analysis_project_created ON analysis(project_key, created_at DESC);
CREATE TABLE IF NOT EXISTS issue (
    project_key       TEXT NOT NULL REFERENCES project(key),
    key               TEXT NOT NULL,
    rule_id           TEXT NOT NULL,
    type              TEXT NOT NULL,
    severity          TEXT NOT NULL,
    message           TEXT NOT NULL,
    file              TEXT NOT NULL,
    line              INT  NOT NULL,
    status            TEXT NOT NULL,
    resolution        TEXT NOT NULL DEFAULT '',
    first_analysis_id TEXT NOT NULL,
    last_analysis_id  TEXT NOT NULL,
    PRIMARY KEY (project_key, key)
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

func (p *Postgres) CreateProject(pr Project) error {
	if pr.Key == "" {
		return fmt.Errorf("project key required")
	}
	ct, err := p.pool.Exec(context.Background(),
		`INSERT INTO project(key, name, created_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
		pr.Key, pr.Name, pr.CreatedAt)
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
		`SELECT key, name, created_at FROM project WHERE key=$1`, key).
		Scan(&pr.Key, &pr.Name, &pr.CreatedAt)
	if err != nil {
		return Project{}, false
	}
	return pr, true
}

func (p *Postgres) ListProjects() []Project {
	rows, err := p.pool.Query(context.Background(),
		`SELECT key, name, created_at FROM project ORDER BY key`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		var pr Project
		if err := rows.Scan(&pr.Key, &pr.Name, &pr.CreatedAt); err == nil {
			out = append(out, pr)
		}
	}
	return out
}

func (p *Postgres) SaveAnalysis(a Analysis, findings []domain.Finding) (Analysis, error) {
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
		`INSERT INTO analysis(id, project_key, created_at, summary, metrics, gate) VALUES ($1,$2,$3,$4,$5,$6)`,
		a.ID, a.ProjectKey, a.CreatedAt, summaryJSON, metricsJSON, gateJSON); err != nil {
		return Analysis{}, err
	}

	seen := make([]string, 0, len(findings))
	for _, f := range findings {
		k := issueKey(f)
		seen = append(seen, k)
		// Upsert: carry over an existing issue (reopening it if it was closed),
		// or insert a new OPEN issue. first_analysis_id is never overwritten.
		if _, err := tx.Exec(ctx, `
INSERT INTO issue(project_key, key, rule_id, type, severity, message, file, line, status, resolution, first_analysis_id, last_analysis_id)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'OPEN','',$9,$9)
ON CONFLICT (project_key, key) DO UPDATE SET
    last_analysis_id = excluded.last_analysis_id,
    line             = excluded.line,
    severity         = excluded.severity,
    status           = CASE WHEN issue.status = 'CLOSED' THEN 'OPEN' ELSE issue.status END,
    resolution       = CASE WHEN issue.status = 'CLOSED' THEN '' ELSE issue.resolution END`,
			a.ProjectKey, k, f.RuleID, string(f.Type), string(f.Severity), f.Message,
			f.Location.File, f.Location.StartLine, a.ID); err != nil {
			return Analysis{}, err
		}
	}

	// Issues open last time but absent now are fixed.
	if _, err := tx.Exec(ctx, `
UPDATE issue SET status='CLOSED', resolution='FIXED', last_analysis_id=$2
WHERE project_key=$1 AND status='OPEN' AND key <> ALL($3)`,
		a.ProjectKey, a.ID, seen); err != nil {
		return Analysis{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Analysis{}, err
	}
	return a, nil
}

func (p *Postgres) LatestAnalysis(projectKey string) (Analysis, bool) {
	var a Analysis
	var summaryJSON, metricsJSON, gateJSON []byte
	err := p.pool.QueryRow(context.Background(), `
SELECT id, project_key, created_at, summary, metrics, gate
FROM analysis WHERE project_key=$1 ORDER BY created_at DESC, id DESC LIMIT 1`, projectKey).
		Scan(&a.ID, &a.ProjectKey, &a.CreatedAt, &summaryJSON, &metricsJSON, &gateJSON)
	if err != nil {
		return Analysis{}, false
	}
	_ = json.Unmarshal(summaryJSON, &a.Summary)
	_ = json.Unmarshal(metricsJSON, &a.Metrics)
	_ = json.Unmarshal(gateJSON, &a.Gate)
	return a, true
}

func (p *Postgres) Issues(projectKey string, openOnly bool) []Issue {
	q := `SELECT project_key, key, rule_id, type, severity, message, file, line, status, resolution, first_analysis_id, last_analysis_id
          FROM issue WHERE project_key=$1`
	if openOnly {
		q += ` AND status='OPEN'`
	}
	q += ` ORDER BY file, line, rule_id`
	rows, err := p.pool.Query(context.Background(), q, projectKey)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Issue
	for rows.Next() {
		var is Issue
		var typ, sev string
		if err := rows.Scan(&is.ProjectKey, &is.Key, &is.RuleID, &typ, &sev, &is.Message,
			&is.File, &is.Line, &is.Status, &is.Resolution, &is.FirstAnalysisID, &is.LastAnalysisID); err != nil {
			continue
		}
		is.Type = domain.IssueType(typ)
		is.Severity = domain.Severity(sev)
		out = append(out, is)
	}
	return out
}

// compile-time check that both stores satisfy the interface.
var (
	_ Store = (*Memory)(nil)
	_ Store = (*Postgres)(nil)
	_       = pgx.ErrNoRows
)
