package main

import (
	"encoding/json"
	"os/exec"
	"testing"
)

// TestCLIEndToEnd builds and runs the actual CLI against the fixture and
// validates that it emits well-formed SARIF with the expected results.
func TestCLIEndToEnd(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "-format", "sarif", "-quiet", "../../testdata/gofixture")
	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run cli: %v\n%s", err, outBytes)
	}

	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(outBytes, &log); err != nil {
		t.Fatalf("output is not valid SARIF JSON: %v\n%s", err, outBytes)
	}
	if log.Version != "2.1.0" {
		t.Errorf("sarif version = %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	if log.Runs[0].Tool.Driver.Name != "codepulse-scan" {
		t.Errorf("driver name = %q", log.Runs[0].Tool.Driver.Name)
	}
	if len(log.Runs[0].Tool.Driver.Rules) == 0 {
		t.Error("expected rule descriptors in driver")
	}
	if len(log.Runs[0].Results) != 4 {
		t.Errorf("sarif results = %d, want 4", len(log.Runs[0].Results))
	}
}

// TestCLIRulesDump runs `codepulse-scan -rules` and validates the emitted
// catalogue is well-formed JSON carrying rule metadata (CWE included).
func TestCLIRulesDump(t *testing.T) {
	out, err := exec.Command("go", "run", ".", "-rules").Output()
	if err != nil {
		t.Fatalf("run cli -rules: %v", err)
	}
	var cat []struct {
		ID       string   `json:"id"`
		Name     string   `json:"name"`
		Language string   `json:"language"`
		Severity string   `json:"severity"`
		CWE      []string `json:"cwe"`
	}
	if err := json.Unmarshal(out, &cat); err != nil {
		t.Fatalf("rules dump is not valid JSON: %v\n%s", err, out)
	}
	if len(cat) < 50 {
		t.Fatalf("catalogue has %d rules, want >= 50", len(cat))
	}
	// py:exec-eval is a known CWE-tagged vulnerability rule.
	var found bool
	for _, r := range cat {
		if r.ID == "py:exec-eval" {
			found = true
			if len(r.CWE) == 0 {
				t.Errorf("py:exec-eval missing CWE mapping")
			}
		}
	}
	if !found {
		t.Errorf("py:exec-eval not present in catalogue")
	}
}
