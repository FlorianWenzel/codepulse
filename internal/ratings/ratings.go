// Package ratings derives SonarQube-style A–E quality ratings and technical
// debt from a scan report.
package ratings

import "github.com/FlorianWenzel/codepulse/internal/domain"

// devCostPerLineMin is the assumed cost to (re)develop one line of code, used
// as the denominator of the technical-debt ratio (SonarQube default: 30 min).
const devCostPerLineMin = 30

// Compute fills rep.Summary.Ratings from the report's findings and size.
func Compute(rep *domain.Report) {
	rep.Summary.Ratings.Reliability = ratingFromWorst(worstSeverity(rep, domain.TypeBug))
	rep.Summary.Ratings.Security = ratingFromWorst(worstSeverity(rep, domain.TypeVulnerability))

	debt := 0
	for _, f := range rep.Findings {
		if f.Type == domain.TypeCodeSmell {
			debt += f.EffortMin
		}
	}
	devCost := rep.Summary.TotalNcloc * devCostPerLineMin
	ratio := 0.0
	if devCost > 0 {
		ratio = float64(debt) / float64(devCost) * 100
	}
	rep.Summary.Ratings.TechDebtMin = debt
	rep.Summary.Ratings.DebtRatio = ratio
	rep.Summary.Ratings.Maintainability = maintainabilityRating(ratio)
}

// worstSeverity returns the most severe finding of a given type, or "" if none.
func worstSeverity(rep *domain.Report, t domain.IssueType) domain.Severity {
	var worst domain.Severity
	for _, f := range rep.Findings {
		if f.Type != t {
			continue
		}
		if worst == "" || f.Severity.AtLeast(worst) {
			worst = f.Severity
		}
	}
	return worst
}

// ratingFromWorst maps the worst issue severity to a reliability/security
// rating: no issues → A, then MINOR→B … BLOCKER→E.
func ratingFromWorst(s domain.Severity) domain.Rating {
	switch s {
	case "":
		return domain.RatingA
	case domain.SevBlocker:
		return domain.RatingE
	case domain.SevCritical:
		return domain.RatingD
	case domain.SevMajor:
		return domain.RatingC
	default: // MINOR / INFO
		return domain.RatingB
	}
}

// maintainabilityRating maps a technical-debt ratio (%) to A–E.
func maintainabilityRating(ratio float64) domain.Rating {
	switch {
	case ratio <= 5:
		return domain.RatingA
	case ratio <= 10:
		return domain.RatingB
	case ratio <= 20:
		return domain.RatingC
	case ratio <= 50:
		return domain.RatingD
	default:
		return domain.RatingE
	}
}
