// Package server exposes CodePulse's HTTP API: project management, analysis
// ingest, and read endpoints for the dashboard.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/server/decorate"
	"github.com/FlorianWenzel/codepulse/internal/server/gate"
	"github.com/FlorianWenzel/codepulse/internal/server/store"
)

// Server is the HTTP API handler.
type Server struct {
	store       store.Store
	gate        gate.Gate
	mux         *http.ServeMux
	now         func() time.Time
	decorator   decorate.Decorator
	authEnabled bool
	oidc        *OIDC
	webhookURL  string
}

// SetWebhook configures a URL that receives a JSON notification after each
// analysis is ingested.
func (s *Server) SetWebhook(url string) { s.webhookURL = url }

// New builds a Server backed by the given store and the default quality gate.
func New(s store.Store) *Server {
	srv := &Server{store: s, gate: gate.Default(), now: time.Now}
	// Seed the default gate so it can be listed/assigned like any other.
	_ = s.SaveGate(store.GateRecord{ID: "default", Name: gate.Default().Name, Conditions: gate.Default().Conditions})
	srv.routes()
	return srv
}

// SetDecorator configures PR decoration (commit-status posting).
func (s *Server) SetDecorator(d decorate.Decorator) { s.decorator = d }

// branchOf returns the requested branch or "main".
func branchOf(r *http.Request) string {
	if b := r.URL.Query().Get("branch"); b != "" {
		return b
	}
	return "main"
}

func (s *Server) routes() {
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("GET /healthz", s.health)
	s.mux.HandleFunc("GET /auth/login", s.login)
	s.mux.HandleFunc("GET /auth/callback", s.callback)
	s.mux.HandleFunc("POST /api/v1/tokens", s.createToken)
	s.mux.HandleFunc("POST /api/v1/projects", s.createProject)
	s.mux.HandleFunc("GET /api/v1/projects", s.listProjects)
	s.mux.HandleFunc("GET /api/v1/projects/{key}", s.getProject)
	s.mux.HandleFunc("POST /api/v1/projects/{key}/prune", s.pruneProject)
	s.mux.HandleFunc("GET /api/v1/portfolio", s.portfolio)
	s.mux.HandleFunc("POST /api/v1/analyses", s.ingest)
	s.mux.HandleFunc("GET /api/v1/issues", s.listIssues)
	s.mux.HandleFunc("GET /api/v1/issues/new", s.listNewIssues)
	s.mux.HandleFunc("POST /api/v1/issues/transition", s.transitionIssue)
	s.mux.HandleFunc("POST /api/v1/issues/assign", s.assignIssue)
	s.mux.HandleFunc("POST /api/v1/issues/comment", s.commentIssue)
	s.mux.HandleFunc("GET /api/v1/hotspots", s.listHotspots)
	s.mux.HandleFunc("POST /api/v1/hotspots/resolve", s.resolveHotspot)
	s.mux.HandleFunc("GET /api/v1/measures", s.measures)
	s.mux.HandleFunc("GET /api/v1/measures/history", s.measuresHistory)
	s.mux.HandleFunc("POST /api/v1/quality-gates", s.createGate)
	s.mux.HandleFunc("GET /api/v1/quality-gates", s.listGates)
	s.mux.HandleFunc("POST /api/v1/projects/{key}/quality-gate", s.assignGate)
	s.mux.HandleFunc("GET /api/v1/quality-gates/status", s.gateStatus)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// --- handlers ---

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r, isAdmin) {
		return
	}
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

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r, func(store.Token) bool { return true }) {
		return
	}
	writeJSON(w, http.StatusOK, s.store.ListProjects())
}

func (s *Server) getProject(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r, canRead(r.PathValue("key"))) {
		return
	}
	p, ok := s.store.GetProject(r.PathValue("key"))
	if !ok {
		httpError(w, http.StatusNotFound, "project not found")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// portfolioEntry is one project's headline status for the overview.
type portfolioEntry struct {
	Key         string         `json:"key"`
	Name        string         `json:"name"`
	GateStatus  string         `json:"gateStatus"`
	Ratings     domain.Ratings `json:"ratings"`
	Ncloc       int            `json:"ncloc"`
	Findings    int            `json:"findings"`
	HasAnalysis bool           `json:"hasAnalysis"`
}

// portfolio returns every project's latest main-branch status (aggregation).
func (s *Server) portfolio(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r, func(store.Token) bool { return true }) {
		return
	}
	var out []portfolioEntry
	for _, p := range s.store.ListProjects() {
		e := portfolioEntry{Key: p.Key, Name: p.Name}
		if a, ok := s.store.LatestAnalysis(p.Key, p.MainBranch); ok {
			e.HasAnalysis = true
			e.GateStatus = a.Gate.Status
			e.Ratings = a.Summary.Ratings
			e.Ncloc = a.Summary.TotalNcloc
			e.Findings = a.Summary.TotalFindings
		}
		out = append(out, e)
	}
	writeJSON(w, http.StatusOK, out)
}

// pruneProject applies retention (keep newest N analyses on a branch).
func (s *Server) pruneProject(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r, isAdmin) {
		return
	}
	key := r.PathValue("key")
	if _, ok := s.store.GetProject(key); !ok {
		httpError(w, http.StatusNotFound, "project not found")
		return
	}
	keep := 30
	if v := r.URL.Query().Get("keep"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			keep = n
		}
	}
	removed, err := s.store.PruneAnalyses(key, branchOf(r), keep)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"removed": removed, "kept": keep})
}

// ingest accepts a scanner report (domain.Report) for ?project=KEY, persists
// an analysis (reconciling issues), evaluates the quality gate, and returns
// the analysis id + gate result.
func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("project")
	if !s.guard(w, r, canIngest(key)) {
		return
	}
	proj, ok := s.store.GetProject(key)
	if !ok {
		httpError(w, http.StatusNotFound, "unknown project; create it first")
		return
	}
	branch := r.URL.Query().Get("branch")
	if branch == "" {
		branch = proj.MainBranch
	}
	base := r.URL.Query().Get("base") // set for PR/feature-branch analyses

	var rep domain.Report
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		httpError(w, http.StatusBadRequest, "invalid report JSON")
		return
	}

	// Evaluate the project's assigned gate, falling back to the default.
	g := s.gate
	if proj.GateID != "" {
		if rec, ok := s.store.GetGate(proj.GateID); ok {
			g = rec.Gate()
		}
	}
	result := gate.Evaluate(g, rep.Summary)
	a := store.Analysis{
		ProjectKey: key,
		Branch:     branch,
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

	resp := map[string]any{"analysisId": saved.ID, "branch": branch, "gate": result}
	if base != "" {
		newIssues := s.store.NewIssues(key, branch, base)
		resp["newIssues"] = len(newIssues)
	}

	// Best-effort PR decoration (no-op unless a decorator is configured).
	if s.decorator != nil {
		commit := r.URL.Query().Get("commit")
		repo := r.URL.Query().Get("repo")
		if repo != "" && commit != "" {
			_ = s.decorator.Decorate(r.Context(), decorate.Status{
				Repo: repo, Commit: commit, GateOK: result.Status == gate.StatusOK,
				Description: "CodePulse quality gate: " + result.Status,
			})
		}
	}

	if s.webhookURL != "" {
		s.notify(r.Context(), map[string]any{
			"project": key, "branch": branch, "analysisId": saved.ID,
			"gateStatus": result.Status, "newIssues": resp["newIssues"],
		})
	}

	writeJSON(w, http.StatusCreated, resp)
}

// notify posts a best-effort JSON notification to the configured webhook.
func (s *Server) notify(ctx context.Context, payload map[string]any) {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
}

func (s *Server) listIssues(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("project")
	if _, ok := s.store.GetProject(key); !ok {
		httpError(w, http.StatusNotFound, "project not found")
		return
	}
	if !s.guard(w, r, canRead(key)) {
		return
	}
	openOnly := r.URL.Query().Get("open") == "true"
	writeJSON(w, http.StatusOK, s.store.Issues(key, branchOf(r), openOnly))
}

func (s *Server) listNewIssues(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("project")
	if _, ok := s.store.GetProject(key); !ok {
		httpError(w, http.StatusNotFound, "project not found")
		return
	}
	if !s.guard(w, r, canRead(key)) {
		return
	}
	base := r.URL.Query().Get("base")
	if base == "" {
		base = "main"
	}
	writeJSON(w, http.StatusOK, s.store.NewIssues(key, branchOf(r), base))
}

func (s *Server) transitionIssue(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r, isAdmin) {
		return
	}
	var body struct{ Project, Branch, Key, Transition string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	is, err := s.store.TransitionIssue(body.Project, orMain(body.Branch), body.Key, body.Transition)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, is)
}

func (s *Server) assignIssue(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r, isAdmin) {
		return
	}
	var body struct{ Project, Branch, Key, Assignee string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	is, err := s.store.AssignIssue(body.Project, orMain(body.Branch), body.Key, body.Assignee)
	if err != nil {
		httpError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, is)
}

func (s *Server) commentIssue(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r, isAdmin) {
		return
	}
	var body struct{ Project, Branch, Key, Author, Text string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	is, err := s.store.CommentIssue(body.Project, orMain(body.Branch), body.Key, body.Author, body.Text, s.now())
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
	if !s.guard(w, r, canRead(key)) {
		return
	}
	writeJSON(w, http.StatusOK, s.store.Hotspots(key, branchOf(r), r.URL.Query().Get("status")))
}

func (s *Server) resolveHotspot(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r, isAdmin) {
		return
	}
	var body struct{ Project, Branch, Key, Resolution string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	h, err := s.store.ResolveHotspot(body.Project, orMain(body.Branch), body.Key, body.Resolution)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) measures(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("project")
	if !s.guard(w, r, canRead(key)) {
		return
	}
	a, ok := s.store.LatestAnalysis(key, branchOf(r))
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

// summaryMetric extracts a named scalar metric from a summary (for trends).
func summaryMetric(s domain.Summary, metric string) float64 {
	switch metric {
	case "ncloc":
		return float64(s.TotalNcloc)
	case "coverage":
		return s.Coverage
	case "duplicated_lines_density":
		return s.DuplicatedLinesDensity
	case "vulnerabilities":
		return float64(s.ByType[domain.TypeVulnerability])
	case "bugs":
		return float64(s.ByType[domain.TypeBug])
	case "code_smells":
		return float64(s.ByType[domain.TypeCodeSmell])
	case "new_findings":
		return float64(s.NewFindings)
	default: // total_findings
		return float64(s.TotalFindings)
	}
}

// measuresHistory returns a metric's value across a branch's analyses (trend).
func (s *Server) measuresHistory(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("project")
	if !s.guard(w, r, canRead(key)) {
		return
	}
	if _, ok := s.store.GetProject(key); !ok {
		httpError(w, http.StatusNotFound, "project not found")
		return
	}
	metric := r.URL.Query().Get("metric")
	if metric == "" {
		metric = "total_findings"
	}
	type point struct {
		AnalysisID string    `json:"analysisId"`
		CreatedAt  time.Time `json:"createdAt"`
		Value      float64   `json:"value"`
	}
	var points []point
	for _, a := range s.store.AnalysisHistory(key, branchOf(r), 0) {
		points = append(points, point{AnalysisID: a.ID, CreatedAt: a.CreatedAt, Value: summaryMetric(a.Summary, metric)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"metric": metric, "points": points})
}

func (s *Server) createGate(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r, isAdmin) {
		return
	}
	var rec store.GateRecord
	if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if rec.ID == "" {
		httpError(w, http.StatusBadRequest, "gate id required")
		return
	}
	if err := s.store.SaveGate(rec); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, rec)
}

func (s *Server) listGates(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r, func(store.Token) bool { return true }) {
		return
	}
	writeJSON(w, http.StatusOK, s.store.ListGates())
}

func (s *Server) assignGate(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r, isAdmin) {
		return
	}
	var body struct{ GateID string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := s.store.SetProjectGate(r.PathValue("key"), body.GateID); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"project": r.PathValue("key"), "gateId": body.GateID})
}

func (s *Server) gateStatus(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("project")
	if !s.guard(w, r, canRead(key)) {
		return
	}
	a, ok := s.store.LatestAnalysis(key, branchOf(r))
	if !ok {
		httpError(w, http.StatusNotFound, "no analysis for project")
		return
	}
	writeJSON(w, http.StatusOK, a.Gate)
}

// orMain returns b or "main" when empty.
func orMain(b string) string {
	if b == "" {
		return "main"
	}
	return b
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
