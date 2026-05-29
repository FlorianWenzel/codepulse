package coverage_test

import (
	"testing"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/importers/coverage"
)

func TestParseLCOV(t *testing.T) {
	data := []byte("SF:pkg/sample.go\nDA:1,5\nDA:2,0\nDA:3,2\nend_of_record\n")
	cov, err := coverage.Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fc := cov["pkg/sample.go"]
	if fc.LinesToCover != 3 || fc.CoveredLines != 2 {
		t.Errorf("got %+v, want {3 2}", fc)
	}
}

func TestParseGoCover(t *testing.T) {
	data := []byte("mode: set\npkg/sample.go:10.2,12.3 2 1\npkg/sample.go:14.2,15.3 1 0\n")
	cov, err := coverage.Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fc := cov["pkg/sample.go"]
	if fc.LinesToCover != 3 || fc.CoveredLines != 2 {
		t.Errorf("got %+v, want {3 2}", fc)
	}
}

func TestParseCobertura(t *testing.T) {
	data := []byte(`<coverage><packages><package><classes>` +
		`<class filename="pkg/sample.go"><lines>` +
		`<line number="1" hits="3"/><line number="2" hits="0"/>` +
		`</lines></class></classes></package></packages></coverage>`)
	cov, err := coverage.Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fc := cov["pkg/sample.go"]
	if fc.LinesToCover != 2 || fc.CoveredLines != 1 {
		t.Errorf("got %+v, want {2 1}", fc)
	}
}

func TestApplyMatchesBySuffix(t *testing.T) {
	rep := domain.Report{
		Metrics: []domain.FileMetrics{{Path: "pkg/sample.go", Ncloc: 10}},
		Summary: domain.Summary{},
	}
	cov := coverage.Coverage{
		"/abs/build/pkg/sample.go": {LinesToCover: 4, CoveredLines: 3},
	}
	coverage.Apply(&rep, cov)
	if rep.Metrics[0].LinesToCover != 4 || rep.Metrics[0].CoveredLines != 3 {
		t.Errorf("file coverage not applied: %+v", rep.Metrics[0])
	}
	if rep.Summary.Coverage != 75 {
		t.Errorf("summary coverage = %.1f, want 75", rep.Summary.Coverage)
	}
}
