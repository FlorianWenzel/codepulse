package sarif_test

import (
	"testing"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/importers/sarif"
)

const sample = `{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "gosec"}},
    "results": [
      {"ruleId": "G404", "level": "warning",
       "message": {"text": "weak random"},
       "locations": [{"physicalLocation": {
         "artifactLocation": {"uri": "main.go"},
         "region": {"startLine": 12, "startColumn": 3, "endLine": 12, "endColumn": 20}}}]},
      {"ruleId": "G101", "level": "error",
       "message": {"text": "hardcoded credentials"},
       "locations": [{"physicalLocation": {
         "artifactLocation": {"uri": "auth.go"},
         "region": {"startLine": 5}}}]}
    ]
  }]
}`

func TestParse(t *testing.T) {
	findings, err := sarif.Parse([]byte(sample))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}
	f := findings[0]
	if f.RuleID != "external:gosec:G404" {
		t.Errorf("ruleId = %q", f.RuleID)
	}
	if f.Severity != domain.SevMinor { // warning -> MINOR
		t.Errorf("severity = %q, want MINOR", f.Severity)
	}
	if f.Location.File != "main.go" || f.Location.StartLine != 12 {
		t.Errorf("location = %+v", f.Location)
	}
	if findings[1].Severity != domain.SevMajor { // error -> MAJOR
		t.Errorf("severity[1] = %q, want MAJOR", findings[1].Severity)
	}
}

func TestMerge(t *testing.T) {
	rep := domain.Report{Summary: domain.Summary{
		BySeverity: map[domain.Severity]int{}, ByType: map[domain.IssueType]int{}, TotalFindings: 3,
	}}
	findings, _ := sarif.Parse([]byte(sample))
	sarif.Merge(&rep, findings)
	if rep.Summary.TotalFindings != 5 {
		t.Errorf("total findings = %d, want 5 (3 + 2 imported)", rep.Summary.TotalFindings)
	}
	if len(rep.Findings) != 2 {
		t.Errorf("findings appended = %d, want 2", len(rep.Findings))
	}
}
