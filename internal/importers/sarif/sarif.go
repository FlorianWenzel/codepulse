// Package sarif imports third-party analyzer results (SARIF 2.1.0) as
// CodePulse findings, so tools like gosec, ESLint, Bandit, and golangci-lint
// can be consolidated into one dashboard.
package sarif

import (
	"encoding/json"
	"fmt"

	"github.com/FlorianWenzel/codepulse/internal/domain"
)

// sarifLog is the subset of SARIF 2.1.0 we read.
type sarifLog struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Name string `json:"name"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine   int `json:"startLine"`
						StartColumn int `json:"startColumn"`
						EndLine     int `json:"endLine"`
						EndColumn   int `json:"endColumn"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

// levelToSeverity maps a SARIF level to a CodePulse severity.
func levelToSeverity(level string) domain.Severity {
	switch level {
	case "error":
		return domain.SevMajor
	case "warning":
		return domain.SevMinor
	default: // note / none / unset
		return domain.SevInfo
	}
}

// Parse converts SARIF bytes into findings. Each result's rule id is
// namespaced as "external:<tool>:<ruleId>" so imported rules never collide
// with first-party ones.
func Parse(data []byte) ([]domain.Finding, error) {
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("sarif: %w", err)
	}
	var out []domain.Finding
	for _, run := range log.Runs {
		tool := run.Tool.Driver.Name
		if tool == "" {
			tool = "external"
		}
		for _, res := range run.Results {
			f := domain.Finding{
				RuleID:   fmt.Sprintf("external:%s:%s", tool, res.RuleID),
				Message:  res.Message.Text,
				Severity: levelToSeverity(res.Level),
				Type:     domain.TypeCodeSmell,
			}
			if len(res.Locations) > 0 {
				r := res.Locations[0].PhysicalLocation
				f.Location = domain.Location{
					File:      r.ArtifactLocation.URI,
					StartLine: r.Region.StartLine, StartCol: r.Region.StartColumn,
					EndLine: r.Region.EndLine, EndCol: r.Region.EndColumn,
				}
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// Merge appends findings to a report and updates its summary counters.
func Merge(rep *domain.Report, findings []domain.Finding) {
	if rep.Summary.BySeverity == nil {
		rep.Summary.BySeverity = map[domain.Severity]int{}
	}
	if rep.Summary.ByType == nil {
		rep.Summary.ByType = map[domain.IssueType]int{}
	}
	for _, f := range findings {
		rep.Findings = append(rep.Findings, f)
		rep.Summary.BySeverity[f.Severity]++
		rep.Summary.ByType[f.Type]++
		rep.Summary.TotalFindings++
	}
}
