package semgrep_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/FlorianWenzel/codepulse/internal/importers/semgrep"
)

// TestRunWithFakeSemgrep stubs the semgrep CLI with a script that emits SARIF,
// verifying CodePulse orchestrates it and ingests the findings.
func TestRunWithFakeSemgrep(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
cat <<'JSON'
{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[
 {"ruleId":"python.lang.security.audit.dangerous-eval","level":"error",
  "message":{"text":"dangerous eval"},
  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"app.py"},"region":{"startLine":7}}}]}
]}]}
JSON
`
	path := filepath.Join(dir, "semgrep")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if !semgrep.Available() {
		t.Fatal("fake semgrep should be on PATH")
	}
	findings, err := semgrep.Run(context.Background(), "p/ci", ".")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.RuleID != "external:semgrep:python.lang.security.audit.dangerous-eval" {
		t.Errorf("ruleId = %q", f.RuleID)
	}
	if f.Location.File != "app.py" || f.Location.StartLine != 7 {
		t.Errorf("location = %+v", f.Location)
	}
}
