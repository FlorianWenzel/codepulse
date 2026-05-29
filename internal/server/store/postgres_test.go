package store_test

import (
	"context"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/server/store"
)

const pgPort = 54329

// TestPostgresStoreIntegration boots a real (embedded) PostgreSQL, applies the
// schema, and exercises persistence + cross-analysis issue tracking.
func TestPostgresStoreIntegration(t *testing.T) {
	cfg := embeddedpostgres.DefaultConfig().
		Username("cp").Password("pg").Database("codepulse").
		Port(pgPort).
		RuntimePath(t.TempDir())
	pg := embeddedpostgres.NewDatabase(cfg)
	if err := pg.Start(); err != nil {
		t.Skipf("embedded postgres unavailable (no network for binary?): %v", err)
	}
	t.Cleanup(func() { _ = pg.Stop() })

	ctx := context.Background()
	dsn := "postgres://cp:pg@localhost:54329/codepulse?sslmode=disable"
	st, err := store.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(st.Close)

	// project create + duplicate
	if err := st.CreateProject(store.Project{Key: "demo", Name: "Demo", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if err := st.CreateProject(store.Project{Key: "demo", Name: "Demo"}); err == nil {
		t.Error("duplicate project should error")
	}
	if _, ok := st.GetProject("demo"); !ok {
		t.Fatal("project not found after create")
	}

	smell := domain.Finding{RuleID: "go:empty-block", Type: domain.TypeCodeSmell, Severity: domain.SevMinor,
		Message: "empty", Location: domain.Location{File: "a.go", StartLine: 3}}
	vuln := domain.Finding{RuleID: "py:exec-eval", Type: domain.TypeVulnerability, Severity: domain.SevCritical,
		Message: "eval", Location: domain.Location{File: "b.py", StartLine: 5}}

	a1, err := st.SaveAnalysis(store.Analysis{ProjectKey: "demo", CreatedAt: time.Now(),
		Summary: domain.Summary{TotalFindings: 2}}, []domain.Finding{smell, vuln})
	if err != nil {
		t.Fatalf("save analysis 1: %v", err)
	}
	if la, ok := st.LatestAnalysis("demo"); !ok || la.ID != a1.ID {
		t.Fatalf("latest analysis mismatch: %+v ok=%v", la, ok)
	}
	if got := len(st.Issues("demo", true)); got != 2 {
		t.Fatalf("after first analysis, open issues = %d, want 2", got)
	}

	// Re-ingest identical findings: tracked, not duplicated.
	if _, err := st.SaveAnalysis(store.Analysis{ProjectKey: "demo", CreatedAt: time.Now()},
		[]domain.Finding{smell, vuln}); err != nil {
		t.Fatalf("save analysis 2: %v", err)
	}
	if got := len(st.Issues("demo", true)); got != 2 {
		t.Errorf("after re-ingest, open issues = %d, want 2 (tracked)", got)
	}

	// Drop the vuln: it should be closed/fixed; smell stays open.
	if _, err := st.SaveAnalysis(store.Analysis{ProjectKey: "demo", CreatedAt: time.Now()},
		[]domain.Finding{smell}); err != nil {
		t.Fatalf("save analysis 3: %v", err)
	}
	open := st.Issues("demo", true)
	if len(open) != 1 || open[0].RuleID != "go:empty-block" {
		t.Errorf("after fix, open issues = %+v, want only the code smell", open)
	}
	all := st.Issues("demo", false)
	if len(all) != 2 {
		t.Errorf("total tracked issues = %d, want 2", len(all))
	}
	var fixed int
	for _, is := range all {
		if is.Status == store.StatusClosed && is.Resolution == store.ResolutionFixed {
			fixed++
		}
	}
	if fixed != 1 {
		t.Errorf("fixed issues = %d, want 1", fixed)
	}
}
