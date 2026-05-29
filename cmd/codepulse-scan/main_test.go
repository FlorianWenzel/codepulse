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
