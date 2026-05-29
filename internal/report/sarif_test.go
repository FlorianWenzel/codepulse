package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/report"
)

func TestWriteSARIFIncludesRuleMetadata(t *testing.T) {
	rep := domain.Report{
		Tool: "codepulse-scan", Version: "test",
		Findings: []domain.Finding{{
			RuleID: "py:exec-eval", Message: "eval", Severity: domain.SevCritical,
			Type: domain.TypeVulnerability, Location: domain.Location{File: "a.py", StartLine: 1, EndLine: 1},
		}},
	}
	meta := []report.RuleMeta{{
		ID: "py:exec-eval", Name: "eval is dangerous", Type: domain.TypeVulnerability,
		Severity: domain.SevCritical, Description: "eval runs arbitrary code",
		CWE: []string{"CWE-95"}, Tags: []string{"security"},
	}}

	var buf bytes.Buffer
	if err := report.WriteSARIF(&buf, rep, meta); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "fullDescription") || !strings.Contains(out, "eval runs arbitrary code") {
		t.Error("SARIF missing rule fullDescription")
	}
	if !strings.Contains(out, "CWE-95") {
		t.Error("SARIF missing CWE mapping")
	}
	// must still be valid JSON
	var v any
	if err := json.Unmarshal(buf.Bytes(), &v); err != nil {
		t.Fatalf("SARIF not valid JSON: %v", err)
	}
}
