// Package server exposes CodePulse's HTTP API: project management, analysis
// ingest, and read endpoints for the dashboard.
package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/server/gate"
	"github.com/FlorianWenzel/codepulse/internal/server/store"
)

// Server is the HTTP API handler.
type Server struct {
	store store.Store
	gate  gate.Gate
	mux   *http.ServeMux
	now   func() time.Time
}

// New builds a Server backed by the given store and the default quality gate.
func New(s store.Store) *Server {
	srv := &Server{store: s, gate: gate.Default(), now: time.Now}
	srv.routes()
	return srv
}

func (s *Server) routes() {
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("GET /healthz", s.health)
	s.mux.HandleFunc("POST /api/v1/projects", s.createProject)
	s.mux.HandleFunc("GET /api/v1/projects", s.listProjects)
	s.mux.HandleFunc("GET /api/v1/projects/{key}", s.getProject)
	s.mux.HandleFunc("POST /api/v1/analyses", s.ingest)
	s.mux.HandleFunc("GET /api/v1/issues", s.listIssues)
	s.mux.HandleFunc("POST /api/v1/issues/transition", s.transitionIssue)
	s.mux.HandleFunc("POST /api/v1/issues/assign", s.assignIssue)
	s.mux.HandleFunc("POST /api/v1/issues/comment", s.commentIssue)
	s.mux.HandleFunc("GET /api/v1/hotspots", s.listHotspots)
	s.mux.HandleFunc("POST /api/v1/hotspots/resolve", s.resolveHotspot)
	s.mux.HandleFunc("GET /api/v1/measures", s.measures)
	s.mux.HandleFunc("GET /api/v1/quality-gates/status", s.gateStatus)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// --- handlers ---

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	var body struct{ Key, Name string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.Key == "" {
		httpError(w, http.StatusBadRequest, "key is required")
		return
	}
	if body.Name == "" {
		body.Name = body.Key
	}
	p := store.Project{Key: body.Key, Name: body.Name, CreatedAt: s.now()}
	if err := s.store.CreateProject(p); err != nil {
		httpError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) listProjects(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.store.ListProjects())
}

func (s *Server) getProject(w http.ResponseWriter, r *http.Request) {
	p, ok := s.store.GetProject(r.PathValue("key"))
	if !ok {
		httpError(w, http.StatusNotFound, "project not found")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// ingest accepts a scanner report (domain.Report) for ?project=KEY, persists
// an analysis (reconciling issues), evaluates the quality gate, and returns
// the analysis id + gate result.
func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("project")
	if _, ok := s.store.GetProject(key); !ok {
		httpError(w, http.StatusNotFound, "unknown project; create it first")
		return
	}
	var rep domain.Report
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		httpError(w, http.StatusBadRequest, "invalid report JSON")
		return
	}

	result := gate.Evaluate(s.gate, rep.Summary)
	a := store.Analysis{
		ProjectKey: key,
		CreatedAt:  s.now(),
		Summary:    rep.Summary,
		Metrics:    rep.Metrics,
		Gate:       result,
	}
	saved, err := s.store.SaveAnalysis(a, rep.Findings)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"analysisId": saved.ID,
		"gate":       result,
	})
}

func (s *Server) listIssues(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("project")
	if _, ok := s.store.GetProject(key); !ok {
		httpError(w, http.StatusNotFound, "project not found")
		return
	}
	openOnly := r.URL.Query().Get("open") == "true"
	writeJSON(w, http.StatusOK, s.store.Issues(key, openOnly))
}

func (s *Server) transitionIssue(w http.ResponseWriter, r *http.Request) {
	var body struct{ Project, Key, Transition string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	is, err := s.store.TransitionIssue(body.Project, body.Key, body.Transition)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, is)
}

func (s *Server) assignIssue(w http.ResponseWriter, r *http.Request) {
	var body struct{ Project, Key, Assignee string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	is, err := s.store.AssignIssue(body.Project, body.Key, body.Assignee)
	if err != nil {
		httpError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, is)
}

func (s *Server) commentIssue(w http.ResponseWriter, r *http.Request) {
	var body struct{ Project, Key, Author, Text string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	is, err := s.store.CommentIssue(body.Project, body.Key, body.Author, body.Text, s.now())
	if err != nil {
		httpError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, is)
}

func (s *Server) listHotspots(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("project")
	if _, ok := s.store.GetProject(key); !ok {
		httpError(w, http.StatusNotFound, "project not found")
		return
	}
	writeJSON(w, http.StatusOK, s.store.Hotspots(key, r.URL.Query().Get("status")))
}

func (s *Server) resolveHotspot(w http.ResponseWriter, r *http.Request) {
	var body struct{ Project, Key, Resolution string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	h, err := s.store.ResolveHotspot(body.Project, body.Key, body.Resolution)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) measures(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("project")
	a, ok := s.store.LatestAnalysis(key)
	if !ok {
		httpError(w, http.StatusNotFound, "no analysis for project")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"analysisId": a.ID,
		"summary":    a.Summary,
		"metrics":    a.Metrics,
	})
}

func (s *Server) gateStatus(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("project")
	a, ok := s.store.LatestAnalysis(key)
	if !ok {
		httpError(w, http.StatusNotFound, "no analysis for project")
		return
	}
	writeJSON(w, http.StatusOK, a.Gate)
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
