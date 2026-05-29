package store

import (
	"fmt"
	"sort"
	"sync"

	"github.com/FlorianWenzel/codepulse/internal/domain"
)

// Memory is an in-memory Store, used for tests and single-node runs. It is
// safe for concurrent use.
type Memory struct {
	mu       sync.Mutex
	projects map[string]Project
	analyses map[string][]Analysis      // projectKey -> analyses (oldest first)
	issues   map[string]map[string]*Issue // projectKey -> issueKey -> issue
	seq      int
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		projects: map[string]Project{},
		analyses: map[string][]Analysis{},
		issues:   map[string]map[string]*Issue{},
	}
}

func (m *Memory) CreateProject(p Project) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.Key == "" {
		return fmt.Errorf("project key required")
	}
	if _, ok := m.projects[p.Key]; ok {
		return fmt.Errorf("project %q already exists", p.Key)
	}
	m.projects[p.Key] = p
	m.issues[p.Key] = map[string]*Issue{}
	return nil
}

func (m *Memory) GetProject(key string) (Project, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.projects[key]
	return p, ok
}

func (m *Memory) ListProjects() []Project {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Project, 0, len(m.projects))
	for _, p := range m.projects {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// issueKey is the stable identity of a finding across analyses: rule + file +
// message (intentionally line-independent so code shifting doesn't create a
// duplicate issue).
func issueKey(f domain.Finding) string {
	return f.RuleID + "|" + f.Location.File + "|" + f.Message
}

func (m *Memory) SaveAnalysis(a Analysis, findings []domain.Finding) (Analysis, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.projects[a.ProjectKey]; !ok {
		return Analysis{}, fmt.Errorf("unknown project %q", a.ProjectKey)
	}

	m.seq++
	a.ID = fmt.Sprintf("a%d", m.seq)

	tracked := m.issues[a.ProjectKey]
	seen := map[string]bool{}

	for _, f := range findings {
		k := issueKey(f)
		seen[k] = true
		if iss, ok := tracked[k]; ok && iss.Status != StatusClosed {
			// carry-over: keep identity/status, update last-seen location.
			iss.LastAnalysisID = a.ID
			iss.Line = f.Location.StartLine
			iss.Severity = f.Severity
			continue
		}
		// new (or reopened) issue.
		tracked[k] = &Issue{
			Key:             k,
			ProjectKey:      a.ProjectKey,
			RuleID:          f.RuleID,
			Type:            f.Type,
			Severity:        f.Severity,
			Message:         f.Message,
			File:            f.Location.File,
			Line:            f.Location.StartLine,
			Status:          StatusOpen,
			FirstAnalysisID: a.ID,
			LastAnalysisID:  a.ID,
		}
	}

	// Issues not seen this run are fixed.
	for k, iss := range tracked {
		if !seen[k] && iss.Status == StatusOpen {
			iss.Status = StatusClosed
			iss.Resolution = ResolutionFixed
			iss.LastAnalysisID = a.ID
		}
	}

	m.analyses[a.ProjectKey] = append(m.analyses[a.ProjectKey], a)
	return a, nil
}

func (m *Memory) LatestAnalysis(projectKey string) (Analysis, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := m.analyses[projectKey]
	if len(list) == 0 {
		return Analysis{}, false
	}
	return list[len(list)-1], true
}

func (m *Memory) Issues(projectKey string, openOnly bool) []Issue {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Issue
	for _, iss := range m.issues[projectKey] {
		if openOnly && iss.Status != StatusOpen {
			continue
		}
		out = append(out, *iss)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}
