package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/server/decorate"
	"github.com/FlorianWenzel/codepulse/internal/server/gate"
	"github.com/FlorianWenzel/codepulse/internal/server/store"
)

// Task tracks the processing of an asynchronously-ingested analysis.
type Task struct {
	ID         string      `json:"id"`
	Status     string      `json:"status"` // queued | running | done | failed
	AnalysisID string      `json:"analysisId,omitempty"`
	Gate       gate.Result `json:"gate,omitempty"`
	NewIssues  int         `json:"newIssues,omitempty"`
	Error      string      `json:"error,omitempty"`
}

// ingestJob is a unit of work for the async ingest workers.
type ingestJob struct {
	taskID     string
	projectKey string
	branch     string
	base       string
	repo       string
	commit     string
	report     domain.Report
}

// EnableAsyncIngest decouples ingest from processing: ingest returns 202 with a
// task id, and a pool of workers persists the analysis + evaluates the gate.
// (The same Queue interface can be backed by a durable Postgres SKIP LOCKED job
// table for multi-node deployments; this in-process pool is the single-node
// default.)
func (s *Server) EnableAsyncIngest(workers int) {
	if workers < 1 {
		workers = 1
	}
	s.async = true
	s.jobs = make(chan ingestJob, 1024)
	s.tasks = map[string]*Task{}
	for i := 0; i < workers; i++ {
		go s.worker()
	}
}

func (s *Server) worker() {
	for j := range s.jobs {
		s.setTask(j.taskID, func(t *Task) { t.Status = "running" })
		id, result, newCount, err := s.runAnalysis(context.Background(), j)
		s.setTask(j.taskID, func(t *Task) {
			if err != nil {
				t.Status, t.Error = "failed", err.Error()
				return
			}
			t.Status, t.AnalysisID, t.Gate, t.NewIssues = "done", id, result, newCount
		})
	}
}

func (s *Server) enqueue(j ingestJob) *Task {
	s.taskMu.Lock()
	s.taskSeq++
	id := fmt.Sprintf("t%d", s.taskSeq)
	t := &Task{ID: id, Status: "queued"}
	s.tasks[id] = t
	j.taskID = id
	s.taskMu.Unlock()
	s.jobs <- j
	return t
}

func (s *Server) setTask(id string, fn func(*Task)) {
	s.taskMu.Lock()
	defer s.taskMu.Unlock()
	if t, ok := s.tasks[id]; ok {
		fn(t)
	}
}

func (s *Server) getTask(id string) (Task, bool) {
	s.taskMu.Lock()
	defer s.taskMu.Unlock()
	t, ok := s.tasks[id]
	if !ok {
		return Task{}, false
	}
	return *t, true
}

func (s *Server) taskStatus(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r, func(store.Token) bool { return true }) {
		return
	}
	t, ok := s.getTask(r.PathValue("id"))
	if !ok {
		httpError(w, http.StatusNotFound, "task not found")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// runAnalysis is the shared processing path for sync and async ingest: resolve
// the project's gate, persist the analysis (reconciling issues), then decorate
// the PR and fire the webhook. Returns the analysis id, gate result, and the
// count of new-vs-base issues (when base is set).
func (s *Server) runAnalysis(ctx context.Context, j ingestJob) (string, gate.Result, int, error) {
	proj, ok := s.store.GetProject(j.projectKey)
	if !ok {
		return "", gate.Result{}, 0, fmt.Errorf("unknown project %q", j.projectKey)
	}
	g := s.gate
	if proj.GateID != "" {
		if rec, ok := s.store.GetGate(proj.GateID); ok {
			g = rec.Gate()
		}
	}
	result := gate.Evaluate(g, j.report.Summary)
	saved, err := s.store.SaveAnalysis(store.Analysis{
		ProjectKey: j.projectKey, Branch: j.branch, CreatedAt: s.now(),
		Summary: j.report.Summary, Metrics: j.report.Metrics, Gate: result,
	}, j.report.Findings)
	if err != nil {
		return "", result, 0, err
	}
	newCount := 0
	if j.base != "" {
		newCount = len(s.store.NewIssues(j.projectKey, j.branch, j.base))
	}
	if s.decorator != nil && j.repo != "" && j.commit != "" {
		_ = s.decorator.Decorate(ctx, decorate.Status{
			Repo: j.repo, Commit: j.commit, GateOK: result.Status == gate.StatusOK,
			Description: "CodePulse quality gate: " + result.Status,
		})
	}
	if s.webhookURL != "" {
		s.notify(ctx, map[string]any{
			"project": j.projectKey, "branch": j.branch, "analysisId": saved.ID,
			"gateStatus": result.Status, "newIssues": newCount,
		})
	}
	return saved.ID, result, newCount, nil
}
