// Package store defines the server's persistence model and an interface with
// pluggable backends (in-memory now; Postgres later).
package store

import (
	"time"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/server/gate"
)

// Project is an analyzed codebase.
type Project struct {
	Key       string    `json:"key"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

// Analysis is one immutable snapshot of a project at a point in time.
type Analysis struct {
	ID         string               `json:"id"`
	ProjectKey string               `json:"projectKey"`
	CreatedAt  time.Time            `json:"createdAt"`
	Summary    domain.Summary       `json:"summary"`
	Metrics    []domain.FileMetrics `json:"metrics"`
	Gate       gate.Result          `json:"gate"`
}

// Issue is a logical problem tracked across analyses.
type Issue struct {
	Key             string           `json:"key"` // stable identity across analyses
	ProjectKey      string           `json:"projectKey"`
	RuleID          string           `json:"ruleId"`
	Type            domain.IssueType `json:"type"`
	Severity        domain.Severity  `json:"severity"`
	Message         string           `json:"message"`
	File            string           `json:"file"`
	Line            int              `json:"line"`
	Status          string           `json:"status"`     // OPEN | CLOSED
	Resolution      string           `json:"resolution"` // "" | FIXED
	FirstAnalysisID string           `json:"firstAnalysisId"`
	LastAnalysisID  string           `json:"lastAnalysisId"`
}

// Issue statuses.
const (
	StatusOpen   = "OPEN"
	StatusClosed = "CLOSED"

	ResolutionFixed = "FIXED"
)

// Store is the server's persistence interface.
type Store interface {
	CreateProject(p Project) error
	GetProject(key string) (Project, bool)
	ListProjects() []Project

	// SaveAnalysis persists an analysis and reconciles its findings against
	// the project's tracked issues (carry-over / new / fixed). It assigns and
	// returns the analysis with its ID populated.
	SaveAnalysis(a Analysis, findings []domain.Finding) (Analysis, error)
	LatestAnalysis(projectKey string) (Analysis, bool)

	// Issues returns the project's tracked issues; openOnly filters to those
	// not yet resolved.
	Issues(projectKey string, openOnly bool) []Issue
}
