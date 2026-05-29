// Package store defines the server's persistence model and an interface with
// pluggable backends (in-memory and Postgres).
package store

import (
	"fmt"
	"time"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/server/gate"
)

// Project is an analyzed codebase.
type Project struct {
	Key        string    `json:"key"`
	Name       string    `json:"name"`
	MainBranch string    `json:"mainBranch"`
	CreatedAt  time.Time `json:"createdAt"`
}

// Analysis is one immutable snapshot of a project at a point in time.
type Analysis struct {
	ID         string               `json:"id"`
	ProjectKey string               `json:"projectKey"`
	Branch     string               `json:"branch"`
	CreatedAt  time.Time            `json:"createdAt"`
	Summary    domain.Summary       `json:"summary"`
	Metrics    []domain.FileMetrics `json:"metrics"`
	Gate       gate.Result          `json:"gate"`
}

// Comment is a note on an issue.
type Comment struct {
	Author string    `json:"author"`
	Text   string    `json:"text"`
	At     time.Time `json:"at"`
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
	Status          string           `json:"status"`
	Resolution      string           `json:"resolution"`
	Assignee        string           `json:"assignee,omitempty"`
	Comments        []Comment        `json:"comments,omitempty"`
	FirstAnalysisID string           `json:"firstAnalysisId"`
	LastAnalysisID  string           `json:"lastAnalysisId"`
}

// Hotspot is a security-sensitive location requiring human review.
type Hotspot struct {
	Key            string `json:"key"`
	ProjectKey     string `json:"projectKey"`
	RuleID         string `json:"ruleId"`
	Message        string `json:"message"`
	File           string `json:"file"`
	Line           int    `json:"line"`
	Status         string `json:"status"`     // TO_REVIEW | REVIEWED
	Resolution     string `json:"resolution"` // "" | SAFE | FIXED | ACKNOWLEDGED
	LastAnalysisID string `json:"lastAnalysisId"`
}

// Token is an API credential. Only its hash is stored; the secret is shown
// once at creation. A global admin token has no ProjectKey; scan/viewer
// tokens are scoped to one project.
type Token struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Role       string    `json:"role"`
	ProjectKey string    `json:"projectKey,omitempty"`
	Hash       string    `json:"-"`
	CreatedAt  time.Time `json:"createdAt"`
}

// Roles.
const (
	RoleAdmin  = "admin"  // global: manage projects/tokens, ingest, triage
	RoleScan   = "scan"   // project-scoped: ingest only
	RoleViewer = "viewer" // project-scoped: read only
)

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool { return r == RoleAdmin || r == RoleScan || r == RoleViewer }

// Issue statuses and resolutions.
const (
	StatusOpen      = "OPEN"
	StatusConfirmed = "CONFIRMED"
	StatusReopened  = "REOPENED"
	StatusClosed    = "CLOSED"

	ResolutionFixed         = "FIXED"
	ResolutionFalsePositive = "FALSE_POSITIVE"
	ResolutionWontFix       = "WONT_FIX"
)

// Hotspot statuses and resolutions.
const (
	HotspotToReview = "TO_REVIEW"
	HotspotReviewed = "REVIEWED"

	HotspotSafe         = "SAFE"
	HotspotFixed        = "FIXED"
	HotspotAcknowledged = "ACKNOWLEDGED"
)

// isOpenStatus reports whether a status counts as currently open (i.e. should
// be re-detected and can be auto-closed when it disappears).
func isOpenStatus(s string) bool {
	return s == StatusOpen || s == StatusConfirmed || s == StatusReopened
}

// stickyResolution reports whether a resolution should survive re-detection
// (manual triage decisions), preventing the issue from reopening.
func stickyResolution(r string) bool {
	return r == ResolutionFalsePositive || r == ResolutionWontFix
}

// applyTransition mutates an issue per a workflow transition, returning an
// error for invalid transitions.
func applyTransition(is *Issue, transition string) error {
	switch transition {
	case "confirm":
		is.Status, is.Resolution = StatusConfirmed, ""
	case "reopen":
		is.Status, is.Resolution = StatusReopened, ""
	case "resolve":
		is.Status, is.Resolution = StatusClosed, ResolutionFixed
	case "falsepositive":
		is.Status, is.Resolution = StatusClosed, ResolutionFalsePositive
	case "wontfix":
		is.Status, is.Resolution = StatusClosed, ResolutionWontFix
	default:
		return fmt.Errorf("unknown transition %q", transition)
	}
	return nil
}

// validHotspotResolution reports whether r is an accepted hotspot resolution.
func validHotspotResolution(r string) bool {
	return r == HotspotSafe || r == HotspotFixed || r == HotspotAcknowledged
}

// Store is the server's persistence interface.
type Store interface {
	CreateProject(p Project) error
	GetProject(key string) (Project, bool)
	ListProjects() []Project

	// SaveAnalysis persists an analysis (on a.Branch) and reconciles its
	// findings against that branch's tracked issues and hotspots.
	SaveAnalysis(a Analysis, findings []domain.Finding) (Analysis, error)
	LatestAnalysis(projectKey, branch string) (Analysis, bool)
	// AnalysisHistory returns a branch's analyses oldest-first (for trends).
	AnalysisHistory(projectKey, branch string, limit int) []Analysis

	Issues(projectKey, branch string, openOnly bool) []Issue
	// NewIssues returns issues on branch whose identity is absent from base
	// (i.e. introduced by this branch/PR).
	NewIssues(projectKey, branch, base string) []Issue
	TransitionIssue(projectKey, branch, key, transition string) (Issue, error)
	AssignIssue(projectKey, branch, key, assignee string) (Issue, error)
	CommentIssue(projectKey, branch, key, author, text string, at time.Time) (Issue, error)

	Hotspots(projectKey, branch, status string) []Hotspot
	ResolveHotspot(projectKey, branch, key, resolution string) (Hotspot, error)

	CreateToken(t Token) error
	AuthToken(hash string) (Token, bool)

	// PruneAnalyses keeps only the most recent keep analyses for a branch and
	// deletes older ones, returning how many were removed (retention).
	PruneAnalyses(projectKey, branch string, keep int) (int, error)
}
