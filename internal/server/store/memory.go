package store

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/FlorianWenzel/codepulse/internal/domain"
)

// Memory is an in-memory Store, used for tests and single-node runs. It is
// safe for concurrent use.
type Memory struct {
	mu       sync.Mutex
	projects map[string]Project
	analyses map[string][]Analysis        // projectKey -> analyses (oldest first)
	issues   map[string]map[string]*Issue // projectKey -> issueKey -> issue
	hotspots map[string]map[string]*Hotspot
	seq      int
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		projects: map[string]Project{},
		analyses: map[string][]Analysis{},
		issues:   map[string]map[string]*Issue{},
		hotspots: map[string]map[string]*Hotspot{},
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
	m.hotspots[p.Key] = map[string]*Hotspot{}
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

// findingKey is the stable identity of a finding across analyses: rule + file
// + message (line-independent so code shifting doesn't create a duplicate).
func findingKey(f domain.Finding) string {
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
	hs := m.hotspots[a.ProjectKey]
	seenIssues := map[string]bool{}
	seenHotspots := map[string]bool{}

	for _, f := range findings {
		k := findingKey(f)
		if f.Type == domain.TypeHotspot {
			seenHotspots[k] = true
			if h, ok := hs[k]; ok {
				h.LastAnalysisID = a.ID
				h.Line = f.Location.StartLine
				continue
			}
			hs[k] = &Hotspot{Key: k, ProjectKey: a.ProjectKey, RuleID: f.RuleID, Message: f.Message,
				File: f.Location.File, Line: f.Location.StartLine, Status: HotspotToReview, LastAnalysisID: a.ID}
			continue
		}

		seenIssues[k] = true
		if iss, ok := tracked[k]; ok {
			iss.LastAnalysisID = a.ID
			iss.Line = f.Location.StartLine
			iss.Severity = f.Severity
			// Reopen only if it was auto-closed (FIXED); manual triage is sticky.
			if iss.Status == StatusClosed && iss.Resolution == ResolutionFixed {
				iss.Status, iss.Resolution = StatusReopened, ""
			}
			continue
		}
		tracked[k] = &Issue{
			Key: k, ProjectKey: a.ProjectKey, RuleID: f.RuleID, Type: f.Type, Severity: f.Severity,
			Message: f.Message, File: f.Location.File, Line: f.Location.StartLine,
			Status: StatusOpen, FirstAnalysisID: a.ID, LastAnalysisID: a.ID,
		}
	}

	// Open issues absent this run are fixed (manual resolutions left alone).
	for k, iss := range tracked {
		if !seenIssues[k] && isOpenStatus(iss.Status) {
			iss.Status, iss.Resolution, iss.LastAnalysisID = StatusClosed, ResolutionFixed, a.ID
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
		if openOnly && !isOpenStatus(iss.Status) {
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

func (m *Memory) TransitionIssue(projectKey, key, transition string) (Issue, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	iss, ok := m.issues[projectKey][key]
	if !ok {
		return Issue{}, fmt.Errorf("issue not found")
	}
	if err := applyTransition(iss, transition); err != nil {
		return Issue{}, err
	}
	return *iss, nil
}

func (m *Memory) AssignIssue(projectKey, key, assignee string) (Issue, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	iss, ok := m.issues[projectKey][key]
	if !ok {
		return Issue{}, fmt.Errorf("issue not found")
	}
	iss.Assignee = assignee
	return *iss, nil
}

func (m *Memory) CommentIssue(projectKey, key, author, text string, at time.Time) (Issue, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	iss, ok := m.issues[projectKey][key]
	if !ok {
		return Issue{}, fmt.Errorf("issue not found")
	}
	iss.Comments = append(iss.Comments, Comment{Author: author, Text: text, At: at})
	return *iss, nil
}

func (m *Memory) Hotspots(projectKey, status string) []Hotspot {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Hotspot
	for _, h := range m.hotspots[projectKey] {
		if status != "" && h.Status != status {
			continue
		}
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out
}

func (m *Memory) ResolveHotspot(projectKey, key, resolution string) (Hotspot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validHotspotResolution(resolution) {
		return Hotspot{}, fmt.Errorf("invalid hotspot resolution %q", resolution)
	}
	h, ok := m.hotspots[projectKey][key]
	if !ok {
		return Hotspot{}, fmt.Errorf("hotspot not found")
	}
	h.Status, h.Resolution = HotspotReviewed, resolution
	return *h, nil
}
