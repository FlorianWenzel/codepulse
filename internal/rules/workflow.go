package rules

import (
	"regexp"
	"strings"

	"github.com/FlorianWenzel/codepulse/internal/domain"
)

// GitHub Actions workflow checks. Untrusted GitHub event context interpolated
// into a workflow (especially a run: step) is a script-injection vector
// (CWE-94) — the attacker controls PR titles, issue bodies, branch names, etc.

// reActionsInjection matches attacker-controllable github.* context expressions
// (the high-risk set from GitHub's security-hardening guidance).
var reActionsInjection = regexp.MustCompile(`\$\{\{\s*github\.(?:head_ref|event\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit)\.[A-Za-z_.]*(?:title|body|message|ref|label|name|email)|event\.pages\.[^.}]+\.page_name|event\.commits\.[^.}]+\.[A-Za-z_.]*(?:message|name|email))`)

// IsWorkflowFile reports whether path is a GitHub Actions workflow.
func IsWorkflowFile(path string) bool {
	p := strings.ReplaceAll(path, `\`, "/")
	if !strings.Contains(p, ".github/workflows/") {
		return false
	}
	return strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml")
}

// ScanWorkflow flags untrusted-context interpolations in a workflow file.
func ScanWorkflow(path string, src []byte) []domain.Finding {
	var out []domain.Finding
	for i, line := range strings.Split(string(src), "\n") {
		if loc := reActionsInjection.FindStringIndex(line); loc != nil {
			out = append(out, domain.Finding{
				RuleID:    "actions:script-injection",
				Message:   "Untrusted GitHub context (PR/issue/branch data) interpolated in a workflow; in a run: step this is script injection. Pass it via an env: var and reference \"$VAR\", or validate it.",
				Severity:  domain.SevCritical,
				Type:      domain.TypeHotspot,
				Location:  domain.Location{File: path, StartLine: i + 1, StartCol: loc[0] + 1, EndLine: i + 1, EndCol: loc[1] + 1},
				EffortMin: 20,
			})
		}
	}
	return out
}

// WorkflowCatalog returns the catalogue entry for the workflow check(s).
func WorkflowCatalog() []Meta {
	return []Meta{{
		ID: "actions:script-injection", Name: "Untrusted GitHub context in a workflow",
		Language: "github-actions", Type: domain.TypeHotspot, Severity: domain.SevCritical, EffortMin: 20,
		Description: "Attacker-controllable github.event context (PR title, issue body, branch name) interpolated into a workflow can inject shell commands in run: steps.",
		Remediation: "Pass the value through an env: variable and reference it quoted (\"$VAR\"); never inline ${{ github.event... }} directly in run:.",
		CWE:         []string{"CWE-94"},
		OWASP:       []string{"A03:2021-Injection"},
		Tags:        []string{"security", "ci", "supply-chain"},
	}}
}
