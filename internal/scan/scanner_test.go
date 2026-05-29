package scan_test

import (
	"testing"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/scan"
)

// TestScanFixtureDir is an end-to-end test of the scan pipeline over a real
// directory: walk → parse → rules → metrics → aggregated report.
func TestScanFixtureDir(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/gofixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Summary.FilesAnalyzed != 1 {
		t.Errorf("files analyzed = %d, want 1", rep.Summary.FilesAnalyzed)
	}
	if rep.Summary.TotalFindings != 4 {
		t.Errorf("total findings = %d, want 4", rep.Summary.TotalFindings)
	}
	if rep.Summary.TotalNcloc == 0 {
		t.Error("expected non-zero ncloc")
	}
	if rep.Summary.ByType[domain.TypeCodeSmell] != 4 {
		t.Errorf("code smells = %d, want 4", rep.Summary.ByType[domain.TypeCodeSmell])
	}

	// findings must be deterministically ordered by line.
	for i := 1; i < len(rep.Findings); i++ {
		a, b := rep.Findings[i-1], rep.Findings[i]
		if a.Location.File == b.Location.File && a.Location.StartLine > b.Location.StartLine {
			t.Errorf("findings not ordered by line: %d before %d", a.Location.StartLine, b.Location.StartLine)
		}
	}
}

func TestScanRelativePaths(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/gofixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, m := range rep.Metrics {
		if m.Path != "sample.go" {
			t.Errorf("metric path = %q, want project-relative sample.go", m.Path)
		}
	}
}

func TestScanPythonFixtureDir(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/pyfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Summary.FilesAnalyzed != 1 {
		t.Errorf("files analyzed = %d, want 1", rep.Summary.FilesAnalyzed)
	}
	if rep.Summary.TotalFindings != 4 {
		t.Errorf("total findings = %d, want 4", rep.Summary.TotalFindings)
	}
	if rep.Language != "python" {
		t.Errorf("language = %q, want python", rep.Language)
	}
	// one of the python findings is a VULNERABILITY (eval/exec)
	if rep.Summary.ByType[domain.TypeVulnerability] != 1 {
		t.Errorf("vulnerabilities = %d, want 1", rep.Summary.ByType[domain.TypeVulnerability])
	}
}

func TestScanRatings(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/pyfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	// pyfixture has a CRITICAL vulnerability (eval) and a MAJOR bug (bare-except).
	if rep.Summary.Ratings.Security != domain.RatingD {
		t.Errorf("security rating = %s, want D (critical vuln)", rep.Summary.Ratings.Security)
	}
	if rep.Summary.Ratings.Reliability != domain.RatingC {
		t.Errorf("reliability rating = %s, want C (major bug)", rep.Summary.Ratings.Reliability)
	}
	if rep.Summary.Ratings.Maintainability == "" {
		t.Error("maintainability rating should be set")
	}
	if rep.Summary.Ratings.TechDebtMin <= 0 {
		t.Error("expected positive technical debt from code smells")
	}
}

func TestScanJavaScript(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/jsfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Language != "javascript" {
		t.Errorf("language = %q, want javascript", rep.Language)
	}
	if rep.Summary.TotalFindings != 5 {
		t.Errorf("findings = %d, want 5", rep.Summary.TotalFindings)
	}
	if rep.Summary.ByType[domain.TypeHotspot] != 1 {
		t.Errorf("security hotspots = %d, want 1 (child-process exec)", rep.Summary.ByType[domain.TypeHotspot])
	}
	if rep.Summary.ByType[domain.TypeVulnerability] != 1 {
		t.Errorf("vulnerabilities = %d, want 1 (eval)", rep.Summary.ByType[domain.TypeVulnerability])
	}
}

func TestScanJava(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/javafixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Language != "java" {
		t.Errorf("language = %q, want java", rep.Language)
	}
	// todo, empty-catch (bug), catch-generic (smell), system-exit, high-complexity
	if rep.Summary.TotalFindings != 5 {
		t.Errorf("findings = %d, want 5", rep.Summary.TotalFindings)
	}
	if rep.Summary.ByType[domain.TypeBug] != 1 {
		t.Errorf("bugs = %d, want 1 (empty catch)", rep.Summary.ByType[domain.TypeBug])
	}
}

func TestScanDuplication(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/dupfixture", MinDupTokens: 20})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Summary.FilesAnalyzed != 2 {
		t.Fatalf("files analyzed = %d, want 2", rep.Summary.FilesAnalyzed)
	}
	if rep.Summary.DuplicatedLines == 0 {
		t.Error("expected duplicated lines across the two identical files")
	}
	if rep.Summary.DuplicatedLinesDensity <= 0 {
		t.Error("expected positive duplication density")
	}
	for _, m := range rep.Metrics {
		if m.DuplicatedLines == 0 {
			t.Errorf("file %s should report duplicated lines", m.Path)
		}
	}
}
