// Package semgrep provides native interop with Semgrep: CodePulse runs the
// semgrep CLI and ingests its findings (via SARIF), so Semgrep's large
// community rulesets are usable from a single CodePulse scan.
package semgrep

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/importers/sarif"
)

// Available reports whether the semgrep CLI is on PATH.
func Available() bool {
	_, err := exec.LookPath("semgrep")
	return err == nil
}

// Run executes `semgrep --sarif --config <config> <target>` and returns the
// findings (namespaced external:semgrep:<rule> by the SARIF importer).
func Run(ctx context.Context, config, target string) ([]domain.Finding, error) {
	if !Available() {
		return nil, fmt.Errorf("semgrep not found on PATH")
	}
	cmd := exec.CommandContext(ctx, "semgrep", "--sarif", "--quiet", "--config", config, target)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("semgrep: %w", err)
	}
	return sarif.Parse(out)
}
