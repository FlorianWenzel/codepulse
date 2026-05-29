package store

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/FlorianWenzel/codepulse/internal/domain"
)

// Memory is an in-memory Store, used for tests and single-node runs. It is
// safe for concurrent use. Issues/hotspots/analyses are namespaced per
// (project, branch).
type Memory struct {
	mu       sync.Mutex
	projects map[string]Project
	analyses map[string][]Analysis        // bkey -> analyses (oldest first)
	issues   map[string]map[string]*Issue // bkey -> issueKey -> issue
	hotspots map[string]map[string]*Hotspot
	tokens   map[string]Token // hash -> token
	seq      int
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		projects: map[string]Project{},
		analyses: map[string][]Analysis{},
		issues:   map[string]map[string]*Issue{},
		hotspots: map[string]map[string]*Hotspot{},
		tokens:   map[string]Token{},
	}
}

func (m *Memory) CreateToken(t Token) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t.Hash == "" {
		return fmt.Errorf("token hash required")
	}
	m.tokens[t.Hash] = t
	return nil
}

func (m *Memory) AuthToken(hash string) (Token, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[hash]
	return t, ok
}

func (m *Memory) PruneAnalyses(projectKey, branch string, keep int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if keep < 0 {
		keep = 0
	}
	bk := bkey(projectKey, branchOrMain(branch))
	list := m.analyses[bk]
	if len(list) <= keep {
		return 0, nil
	}
	removed := len(list) - keep
	m.analyses[bk] = append([]Analysis(nil), list[removed:]...) // keep newest `keep`
	return removed, nil
}

func branchOrMain(b string) string {
	if b == "" {
		return "main"
	}
	return b
}

// bkey is the per-branch namespace key.
func bkey(project, branch string) string { return project + "\x00" + branch }

func (m *Memory) CreateProject(p Project) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.Key == "" {
		return fmt.Errorf("project key required")
	}
	if _, ok := m.projects[p.Key]; ok {
		return fmt.Errorf("project %q already exists", p.Key)
	}
	if p.MainBranch == "" {
		p.MainBranch = "main"
	}
	m.projects[p.Key] = p
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
	if a.Branch == "" {
		a.Branch = "main"
	}
	bk := bkey(a.ProjectKey, a.Branch)

	m.seq++
	a.ID = fmt.Sprintf("a%d", m.seq)

	if m.issues[bk] == nil {
		m.issues[bk] = map[string]*Issue{}
		m.hotspots[bk] = map[string]*Hotspot{}
	}
	tracked := m.issues[bk]
	hs := m.hotspots[bk]
	seenIssues := map[string]bool{}

	for _, f := range findings {
		k := findingKey(f)
		if f.Type == domain.TypeHotspot {
			if h, ok := hs[k]; ok {
				h.LastAnalysisID, h.Line = a.ID, f.Location.StartLine
				continue
			}
			hs[k] = &Hotspot{Key: k, ProjectKey: a.ProjectKey, RuleID: f.RuleID, Message: f.Message,
				File: f.Location.File, Line: f.Location.StartLine, Status: HotspotToReview, LastAnalysisID: a.ID}
			continue
		}

		seenIssues[k] = true
		if iss, ok := tracked[k]; ok {
			iss.LastAnalysisID, iss.Line, iss.Severity = a.ID, f.Location.StartLine, f.Severity
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

	for k, iss := range tracked {
		if !seenIssues[k] && isOpenStatus(iss.Status) {
			iss.Status, iss.Resolution, iss.LastAnalysisID = StatusClosed, ResolutionFixed, a.ID
		}
	}

	m.analyses[bk] = append(m.analyses[bk], a)
	return a, nil
}

func (m *Memory) LatestAnalysis(projectKey, branch string) (Analysis, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := m.analyses[bkey(projectKey, branch)]
	if len(list) == 0 {
		return Analysis{}, false
	}
	return list[len(list)-1], true
}

func (m *Memory) Issues(projectKey, branch string, openOnly bool) []Issue {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.issuesLocked(projectKey, branch, openOnly)
}

func (m *Memory) issuesLocked(projectKey, branch string, openOnly bool) []Issue {
	var out []Issue
	for _, iss := range m.issues[bkey(projectKey, branch)] {
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

func (m *Memory) NewIssues(projectKey, branch, base string) []Issue {
	m.mu.Lock()
	defer m.mu.Unlock()
	baseKeys := map[string]bool{}
	for k := range m.issues[bkey(projectKey, base)] {
		baseKeys[k] = true
	}
	var out []Issue
	for _, iss := range m.issuesLocked(projectKey, branch, true) {
		if !baseKeys[iss.Key] {
			out = append(out, iss)
		}
	}
	return out
}

func (m *Memory) TransitionIssue(projectKey, branch, key, transition string) (Issue, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	iss, ok := m.issues[bkey(projectKey, branch)][key]
	if !ok {
		return Issue{}, fmt.Errorf("issue not found")
	}
	if err := applyTransition(iss, transition); err != nil {
		return Issue{}, err
	}
	return *iss, nil
}

func (m *Memory) AssignIssue(projectKey, branch, key, assignee string) (Issue, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	iss, ok := m.issues[bkey(projectKey, branch)][key]
	if !ok {
		return Issue{}, fmt.Errorf("issue not found")
	}
	iss.Assignee = assignee
	return *iss, nil
}

func (m *Memory) CommentIssue(projectKey, branch, key, author, text string, at time.Time) (Issue, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	iss, ok := m.issues[bkey(projectKey, branch)][key]
	if !ok {
		return Issue{}, fmt.Errorf("issue not found")
	}
	iss.Comments = append(iss.Comments, Comment{Author: author, Text: text, At: at})
	return *iss, nil
}

func (m *Memory) Hotspots(projectKey, branch, status string) []Hotspot {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Hotspot
	for _, h := range m.hotspots[bkey(projectKey, branch)] {
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

func (m *Memory) ResolveHotspot(projectKey, branch, key, resolution string) (Hotspot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validHotspotResolution(resolution) {
		return Hotspot{}, fmt.Errorf("invalid hotspot resolution %q", resolution)
	}
	h, ok := m.hotspots[bkey(projectKey, branch)][key]
	if !ok {
		return Hotspot{}, fmt.Errorf("hotspot not found")
	}
	h.Status, h.Resolution = HotspotReviewed, resolution
	return *h, nil
}
