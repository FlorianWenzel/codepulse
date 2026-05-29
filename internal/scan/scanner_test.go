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
