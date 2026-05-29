// Package gate defines quality gates and evaluates them against a project's
// measures.
package gate

import (
	"fmt"

	"github.com/FlorianWenzel/codepulse/internal/domain"
)

// Op is a comparison that, when true for the actual value, fails the condition.
type Op string

const (
	OpLT Op = "LT" // fail if actual < threshold (e.g. coverage < 80)
	OpGT Op = "GT" // fail if actual > threshold (e.g. vulnerabilities > 0)
	OpEQ Op = "EQ"
	OpNE Op = "NE"
)

// Condition is one quality-gate check on a named metric.
type Condition struct {
	Metric    string  `json:"metric"`
	Op        Op      `json:"op"`
	Threshold float64 `json:"threshold"`
}

// Gate is a named set of conditions.
type Gate struct {
	Name       string      `json:"name"`
	Conditions []Condition `json:"conditions"`
}

// ConditionResult is the outcome of evaluating one condition.
type ConditionResult struct {
	Metric    string  `json:"metric"`
	Op        Op      `json:"op"`
	Threshold float64 `json:"threshold"`
	Actual    float64 `json:"actual"`
	Available bool    `json:"available"`
	Passed    bool    `json:"passed"`
}

// Result is the overall gate outcome.
type Result struct {
	Status     string            `json:"status"` // OK | ERROR
	Conditions []ConditionResult `json:"conditions"`
}

// Gate statuses.
const (
	StatusOK    = "OK"
	StatusError = "ERROR"
)

// Default returns CodePulse's default quality gate.
func Default() Gate {
	return Gate{
		Name: "CodePulse Way",
		Conditions: []Condition{
			{Metric: "vulnerabilities", Op: OpGT, Threshold: 0},
			{Metric: "blocker_issues", Op: OpGT, Threshold: 0},
			{Metric: "duplicated_lines_density", Op: OpGT, Threshold: 3},
			{Metric: "coverage", Op: OpLT, Threshold: 80},
			// Clean-as-you-code: nothing new and dangerous on the changed code.
			{Metric: "new_vulnerabilities", Op: OpGT, Threshold: 0},
			{Metric: "new_blocker_issues", Op: OpGT, Threshold: 0},
		},
	}
}

// Evaluate runs the gate against a project summary. Conditions whose metric is
// unavailable (e.g. coverage with no imported report) are skipped.
func Evaluate(g Gate, s domain.Summary) Result {
	res := Result{Status: StatusOK}
	for _, c := range g.Conditions {
		actual, ok := metricValue(s, c.Metric)
		cr := ConditionResult{Metric: c.Metric, Op: c.Op, Threshold: c.Threshold, Actual: actual, Available: ok, Passed: true}
		if ok && triggered(c.Op, actual, c.Threshold) {
			cr.Passed = false
			res.Status = StatusError
		}
		res.Conditions = append(res.Conditions, cr)
	}
	return res
}

func triggered(op Op, actual, threshold float64) bool {
	switch op {
	case OpLT:
		return actual < threshold
	case OpGT:
		return actual > threshold
	case OpEQ:
		return actual == threshold
	case OpNE:
		return actual != threshold
	}
	return false
}

// ratingValue maps an A–E rating to a number (A=1 … E=5) for comparisons.
func ratingValue(r domain.Rating) float64 {
	switch r {
	case domain.RatingA:
		return 1
	case domain.RatingB:
		return 2
	case domain.RatingC:
		return 3
	case domain.RatingD:
		return 4
	case domain.RatingE:
		return 5
	}
	return 0
}

// metricValue extracts a named metric from a summary, reporting availability.
func metricValue(s domain.Summary, metric string) (float64, bool) {
	switch metric {
	case "vulnerabilities":
		return float64(s.ByType[domain.TypeVulnerability]), true
	case "bugs":
		return float64(s.ByType[domain.TypeBug]), true
	case "code_smells":
		return float64(s.ByType[domain.TypeCodeSmell]), true
	case "security_hotspots":
		return float64(s.ByType[domain.TypeHotspot]), true
	case "blocker_issues":
		return float64(s.BySeverity[domain.SevBlocker]), true
	case "critical_issues":
		return float64(s.BySeverity[domain.SevCritical]), true
	case "major_issues":
		return float64(s.BySeverity[domain.SevMajor]), true
	case "total_findings":
		return float64(s.TotalFindings), true
	case "ncloc":
		return float64(s.TotalNcloc), true
	case "duplicated_lines_density":
		return s.DuplicatedLinesDensity, true
	case "coverage":
		if s.LinesToCover == 0 {
			return 0, false // no coverage data imported
		}
		return s.Coverage, true
	case "new_findings":
		return float64(s.NewFindings), true
	case "new_vulnerabilities":
		return float64(s.NewByType[domain.TypeVulnerability]), true
	case "new_bugs":
		return float64(s.NewByType[domain.TypeBug]), true
	case "new_code_smells":
		return float64(s.NewByType[domain.TypeCodeSmell]), true
	case "new_blocker_issues":
		return float64(s.NewBySeverity[domain.SevBlocker]), true
	case "new_critical_issues":
		return float64(s.NewBySeverity[domain.SevCritical]), true
	case "reliability_rating":
		return ratingValue(s.Ratings.Reliability), true
	case "security_rating":
		return ratingValue(s.Ratings.Security), true
	case "maintainability_rating":
		return ratingValue(s.Ratings.Maintainability), true
	default:
		return 0, false
	}
}

// Describe renders a condition as text (for logs/UI).
func (c Condition) Describe() string {
	return fmt.Sprintf("%s %s %g", c.Metric, c.Op, c.Threshold)
}
