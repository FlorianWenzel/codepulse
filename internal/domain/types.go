// Package domain holds the core, dependency-free types shared across the
// scanner: findings, metrics, and the analysis report.
package domain

// Severity ranks how urgent a finding is, from most to least severe.
type Severity string

const (
	SevBlocker  Severity = "BLOCKER"
	SevCritical Severity = "CRITICAL"
	SevMajor    Severity = "MAJOR"
	SevMinor    Severity = "MINOR"
	SevInfo     Severity = "INFO"
)

// severityRank orders severities so callers can compare them (higher = worse).
var severityRank = map[Severity]int{
	SevInfo: 0, SevMinor: 1, SevMajor: 2, SevCritical: 3, SevBlocker: 4,
}

// AtLeast reports whether s is at least as severe as min.
func (s Severity) AtLeast(min Severity) bool {
	return severityRank[s] >= severityRank[min]
}

// IssueType classifies a finding into one of CodePulse's families.
type IssueType string

const (
	TypeBug           IssueType = "BUG"
	TypeVulnerability IssueType = "VULNERABILITY"
	TypeCodeSmell     IssueType = "CODE_SMELL"
	TypeHotspot       IssueType = "SECURITY_HOTSPOT"
)

// Location is a 1-based, inclusive-start range within a single file.
type Location struct {
	File      string `json:"file"`
	StartLine int    `json:"startLine"`
	StartCol  int    `json:"startCol"`
	EndLine   int    `json:"endLine"`
	EndCol    int    `json:"endCol"`
}

// Finding is one rule violation at one location.
type Finding struct {
	RuleID    string    `json:"ruleId"`
	Message   string    `json:"message"`
	Severity  Severity  `json:"severity"`
	Type      IssueType `json:"type"`
	Location  Location  `json:"location"`
	EffortMin int       `json:"effortMin"`
}

// FileMetrics holds the size/complexity measures computed for one file.
type FileMetrics struct {
	Path                 string `json:"path"`
	Lines                int    `json:"lines"`
	Ncloc                int    `json:"ncloc"` // non-comment lines of code
	CommentLines         int    `json:"commentLines"`
	Functions            int    `json:"functions"`
	Complexity           int    `json:"complexity"`           // cyclomatic, whole file
	CognitiveComplexity  int    `json:"cognitiveComplexity"`  // whole file
	MaxFuncComplexity    int    `json:"maxFuncComplexity"`    // worst single function
}

// Report is the full result of a scan: every finding, every file's metrics,
// and rolled-up totals.
type Report struct {
	Tool     string        `json:"tool"`
	Version  string        `json:"version"`
	Language string        `json:"language"`
	Findings []Finding     `json:"findings"`
	Metrics  []FileMetrics `json:"metrics"`
	Summary  Summary       `json:"summary"`
}

// Summary is the project-level rollup shown at the end of a scan.
type Summary struct {
	FilesAnalyzed int                `json:"filesAnalyzed"`
	TotalNcloc    int                `json:"totalNcloc"`
	TotalFindings int                `json:"totalFindings"`
	BySeverity    map[Severity]int   `json:"bySeverity"`
	ByType        map[IssueType]int  `json:"byType"`
}
