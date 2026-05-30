package rules

import (
	"regexp"
	"strings"

	"github.com/FlorianWenzel/codepulse/internal/domain"
)

// secretPattern is a high-precision regex for a known credential format. These
// are content-based (not AST) and run over the raw source of every scanned
// file, complementing the name-based <lang>:hardcoded-credentials rules.
type secretPattern struct {
	id   string
	name string
	re   *regexp.Regexp
}

// secretPatterns intentionally favours precision: each matches a specific,
// structured token format that is very unlikely to occur by chance.
var secretPatterns = []secretPattern{
	{"secret:aws-access-key-id", "AWS access key ID", regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b`)},
	{"secret:github-token", "GitHub token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36}\b`)},
	{"secret:github-fine-grained-pat", "GitHub fine-grained PAT", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{40,}\b`)},
	{"secret:google-api-key", "Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{"secret:slack-token", "Slack token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`)},
	{"secret:stripe-secret-key", "Stripe secret key", regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{24,}\b`)},
	{"secret:slack-webhook", "Slack webhook URL", regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z]{20,}`)},
	{"secret:private-key", "Private key block", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)},
}

// ScanSecrets runs the secret patterns over src and returns findings with
// 1-based line/column locations.
func ScanSecrets(path string, src []byte) []domain.Finding {
	var out []domain.Finding
	for i, line := range strings.Split(string(src), "\n") {
		for _, p := range secretPatterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				out = append(out, domain.Finding{
					RuleID:    p.id,
					Message:   p.name + " committed in source; remove it, rotate the credential, and load it from the environment or a secrets manager.",
					Severity:  domain.SevBlocker,
					Type:      domain.TypeVulnerability,
					Location:  domain.Location{File: path, StartLine: i + 1, StartCol: loc[0] + 1, EndLine: i + 1, EndCol: loc[1] + 1},
					EffortMin: 30,
				})
			}
		}
	}
	return out
}

// SecretCatalog returns catalogue entries for the secret patterns so they show
// up in `-rules`, the dashboard, and SARIF rule descriptors alongside AST rules.
func SecretCatalog() []Meta {
	out := make([]Meta, 0, len(secretPatterns))
	for _, p := range secretPatterns {
		out = append(out, Meta{
			ID: p.id, Name: p.name, Language: "any",
			Type: domain.TypeVulnerability, Severity: domain.SevBlocker, EffortMin: 30,
			Description: "A " + p.name + " was found committed in source code (high-precision pattern match).",
			Remediation: "Remove the secret, rotate it immediately, and load it from the environment or a secrets manager. Add a pre-commit secret scan.",
			CWE:         []string{"CWE-798"},
			OWASP:       []string{"A07:2021-Identification and Authentication Failures"},
			Tags:        []string{"security", "secrets"},
		})
	}
	return out
}
