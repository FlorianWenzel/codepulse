package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/rules"
	"github.com/FlorianWenzel/codepulse/internal/scan"
	"github.com/FlorianWenzel/codepulse/internal/server"
	"github.com/FlorianWenzel/codepulse/internal/server/decorate"
	"github.com/FlorianWenzel/codepulse/internal/server/gate"
	"github.com/FlorianWenzel/codepulse/internal/server/store"
)

// TestServerEndToEnd exercises the full API: create a project, scan a fixture,
// ingest the report, then read back issues/measures/gate — and confirm a
// second ingest of the same report tracks issues instead of duplicating them.
func TestServerEndToEnd(t *testing.T) {
	ts := httptest.NewServer(server.New(store.NewMemory()))
	defer ts.Close()

	// 1. create project
	mustPost(t, ts.URL+"/api/v1/projects", map[string]string{"key": "demo", "name": "Demo"}, http.StatusCreated)

	// 2. scan a fixture to produce a real report
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/pyfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// 3. ingest
	var ingestResp struct {
		AnalysisID string      `json:"analysisId"`
		Gate       gate.Result `json:"gate"`
	}
	postJSON(t, ts.URL+"/api/v1/analyses?project=demo", rep, http.StatusCreated, &ingestResp)
	if ingestResp.AnalysisID == "" {
		t.Fatal("no analysis id returned")
	}
	// pyfixture has a vulnerability → default gate must fail.
	if ingestResp.Gate.Status != gate.StatusError {
		t.Errorf("gate status = %s, want ERROR", ingestResp.Gate.Status)
	}

	// 4. issues
	var issues []store.Issue
	getJSON(t, ts.URL+"/api/v1/issues?project=demo&open=true", http.StatusOK, &issues)
	if len(issues) != 4 {
		t.Errorf("open issues = %d, want 4", len(issues))
	}
	var vulns int
	for _, is := range issues {
		if is.Type == domain.TypeVulnerability {
			vulns++
		}
	}
	if vulns != 1 {
		t.Errorf("vulnerability issues = %d, want 1", vulns)
	}

	// 5. measures
	var measures struct {
		Summary domain.Summary `json:"summary"`
	}
	getJSON(t, ts.URL+"/api/v1/measures?project=demo", http.StatusOK, &measures)
	if measures.Summary.TotalFindings != 4 {
		t.Errorf("measures findings = %d, want 4", measures.Summary.TotalFindings)
	}

	// 6. gate status endpoint
	var gateResult gate.Result
	getJSON(t, ts.URL+"/api/v1/quality-gates/status?project=demo", http.StatusOK, &gateResult)
	if gateResult.Status != gate.StatusError {
		t.Errorf("gate-status endpoint = %s, want ERROR", gateResult.Status)
	}

	// 7. re-ingest the same report: issues must be tracked, not duplicated.
	postJSON(t, ts.URL+"/api/v1/analyses?project=demo", rep, http.StatusCreated, &ingestResp)
	var issues2 []store.Issue
	getJSON(t, ts.URL+"/api/v1/issues?project=demo&open=true", http.StatusOK, &issues2)
	if len(issues2) != 4 {
		t.Errorf("after re-ingest, open issues = %d, want 4 (tracked, not duplicated)", len(issues2))
	}
}

// TestIssueAndHotspotWorkflow covers triage: transition (sticky false-positive),
// assign, comment, and the hotspot review workflow.
func TestIssueAndHotspotWorkflow(t *testing.T) {
	ts := httptest.NewServer(server.New(store.NewMemory()))
	defer ts.Close()

	mustPost(t, ts.URL+"/api/v1/projects", map[string]string{"key": "demo", "name": "Demo"}, http.StatusCreated)

	// jsfixture: 5 findings = 4 issues + 1 hotspot (child-process exec)
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/jsfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var ing struct {
		AnalysisID string `json:"analysisId"`
	}
	postJSON(t, ts.URL+"/api/v1/analyses?project=demo", rep, http.StatusCreated, &ing)

	var issues []store.Issue
	getJSON(t, ts.URL+"/api/v1/issues?project=demo&open=true", http.StatusOK, &issues)
	if len(issues) != 4 {
		t.Fatalf("open issues = %d, want 4", len(issues))
	}
	var hotspots []store.Hotspot
	getJSON(t, ts.URL+"/api/v1/hotspots?project=demo&status=TO_REVIEW", http.StatusOK, &hotspots)
	if len(hotspots) != 1 {
		t.Fatalf("hotspots to review = %d, want 1", len(hotspots))
	}

	// mark an issue as false positive
	key := issues[0].Key
	var updated store.Issue
	postJSON(t, ts.URL+"/api/v1/issues/transition",
		map[string]string{"project": "demo", "key": key, "transition": "falsepositive"}, http.StatusOK, &updated)
	if updated.Status != store.StatusClosed || updated.Resolution != store.ResolutionFalsePositive {
		t.Errorf("after FP transition: status=%s resolution=%s", updated.Status, updated.Resolution)
	}

	// assign + comment
	postJSON(t, ts.URL+"/api/v1/issues/assign",
		map[string]string{"project": "demo", "key": key, "assignee": "alice"}, http.StatusOK, &updated)
	if updated.Assignee != "alice" {
		t.Errorf("assignee = %q, want alice", updated.Assignee)
	}
	postJSON(t, ts.URL+"/api/v1/issues/comment",
		map[string]string{"project": "demo", "key": key, "author": "bob", "text": "reviewed, not exploitable"}, http.StatusOK, &updated)
	if len(updated.Comments) != 1 || updated.Comments[0].Author != "bob" {
		t.Errorf("comment not recorded: %+v", updated.Comments)
	}

	// re-ingest: false positive is sticky, so open issues drop to 3
	postJSON(t, ts.URL+"/api/v1/analyses?project=demo", rep, http.StatusCreated, &ing)
	var issues2 []store.Issue
	getJSON(t, ts.URL+"/api/v1/issues?project=demo&open=true", http.StatusOK, &issues2)
	if len(issues2) != 3 {
		t.Errorf("after re-ingest, open issues = %d, want 3 (FP stayed closed)", len(issues2))
	}

	// review the hotspot
	var hres store.Hotspot
	postJSON(t, ts.URL+"/api/v1/hotspots/resolve",
		map[string]string{"project": "demo", "key": hotspots[0].Key, "resolution": "SAFE"}, http.StatusOK, &hres)
	if hres.Status != store.HotspotReviewed || hres.Resolution != store.HotspotSafe {
		t.Errorf("hotspot after resolve: status=%s resolution=%s", hres.Status, hres.Resolution)
	}
	var hs2 []store.Hotspot
	getJSON(t, ts.URL+"/api/v1/hotspots?project=demo&status=TO_REVIEW", http.StatusOK, &hs2)
	if len(hs2) != 0 {
		t.Errorf("hotspots to review after resolve = %d, want 0", len(hs2))
	}
}

// fakeDecorator captures decoration calls.
type fakeDecorator struct{ statuses []decorate.Status }

func (f *fakeDecorator) Decorate(_ context.Context, s decorate.Status) error {
	f.statuses = append(f.statuses, s)
	return nil
}

// TestBranchAnalysisAndDecoration ingests on main and on a feature branch with
// base=main, verifies "new issues" are the branch-introduced ones, and that
// PR decoration is invoked with the gate result.
func TestBranchAnalysisAndDecoration(t *testing.T) {
	srv := server.New(store.NewMemory())
	fd := &fakeDecorator{}
	srv.SetDecorator(fd)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	mustPost(t, ts.URL+"/api/v1/projects", map[string]string{"key": "demo"}, http.StatusCreated)

	// main: python project (4 issues)
	mainRep, _ := scan.Scan(scan.Options{Root: "../../testdata/pyfixture"})
	var resp map[string]any
	postJSON(t, ts.URL+"/api/v1/analyses?project=demo&repo=acme/app&commit=abc123", mainRep, http.StatusCreated, &resp)
	if len(fd.statuses) != 1 || fd.statuses[0].Commit != "abc123" {
		t.Fatalf("expected decoration for main commit, got %+v", fd.statuses)
	}
	if fd.statuses[0].GateOK {
		t.Error("gate should fail (pyfixture has a vulnerability)")
	}

	// feature branch: javascript project (different issues), base=main
	featRep, _ := scan.Scan(scan.Options{Root: "../../testdata/jsfixture"})
	postJSON(t, ts.URL+"/api/v1/analyses?project=demo&branch=feature&base=main", featRep, http.StatusCreated, &resp)
	// jsfixture: 4 issues + 1 hotspot; none share keys with python main → all 4 new
	if got, _ := resp["newIssues"].(float64); int(got) != 4 {
		t.Errorf("newIssues = %v, want 4", resp["newIssues"])
	}

	// the dedicated endpoint agrees
	var newIssues []store.Issue
	getJSON(t, ts.URL+"/api/v1/issues/new?project=demo&branch=feature&base=main", http.StatusOK, &newIssues)
	if len(newIssues) != 4 {
		t.Errorf("GET issues/new = %d, want 4", len(newIssues))
	}

	// main and feature branches are isolated
	var mainIssues []store.Issue
	getJSON(t, ts.URL+"/api/v1/issues?project=demo&branch=main&open=true", http.StatusOK, &mainIssues)
	if len(mainIssues) != 4 {
		t.Errorf("main issues = %d, want 4 (python)", len(mainIssues))
	}
}

func TestPortfolio(t *testing.T) {
	ts := httptest.NewServer(server.New(store.NewMemory()))
	defer ts.Close()
	mustPost(t, ts.URL+"/api/v1/projects", map[string]string{"key": "a", "name": "A"}, http.StatusCreated)
	mustPost(t, ts.URL+"/api/v1/projects", map[string]string{"key": "b", "name": "B"}, http.StatusCreated)

	rep, _ := scan.Scan(scan.Options{Root: "../../testdata/pyfixture"})
	var ignore map[string]any
	postJSON(t, ts.URL+"/api/v1/analyses?project=a", rep, http.StatusCreated, &ignore)

	var entries []struct {
		Key         string `json:"key"`
		GateStatus  string `json:"gateStatus"`
		HasAnalysis bool   `json:"hasAnalysis"`
		Ratings     struct {
			Security string `json:"security"`
		} `json:"ratings"`
	}
	getJSON(t, ts.URL+"/api/v1/portfolio", http.StatusOK, &entries)
	if len(entries) != 2 {
		t.Fatalf("portfolio entries = %d, want 2", len(entries))
	}
	byKey := map[string]int{}
	for i, e := range entries {
		byKey[e.Key] = i
	}
	a := entries[byKey["a"]]
	if !a.HasAnalysis || a.GateStatus != gate.StatusError || a.Ratings.Security != "D" {
		t.Errorf("project a entry wrong: %+v", a)
	}
	if entries[byKey["b"]].HasAnalysis {
		t.Errorf("project b should have no analysis yet")
	}
}

func TestRetentionPrune(t *testing.T) {
	ts := httptest.NewServer(server.New(store.NewMemory()))
	defer ts.Close()
	mustPost(t, ts.URL+"/api/v1/projects", map[string]string{"key": "p"}, http.StatusCreated)

	rep, _ := scan.Scan(scan.Options{Root: "../../testdata/gofixture"})
	var ignore map[string]any
	for i := 0; i < 3; i++ {
		postJSON(t, ts.URL+"/api/v1/analyses?project=p", rep, http.StatusCreated, &ignore)
	}

	var pruneResp struct{ Removed, Kept int }
	postJSON(t, ts.URL+"/api/v1/projects/p/prune?keep=1", nil, http.StatusOK, &pruneResp)
	if pruneResp.Removed != 2 || pruneResp.Kept != 1 {
		t.Errorf("prune result = %+v, want removed=2 kept=1", pruneResp)
	}
	// latest analysis still resolvable after pruning
	var measures map[string]any
	getJSON(t, ts.URL+"/api/v1/measures?project=p", http.StatusOK, &measures)
	if measures["analysisId"] == nil {
		t.Error("expected a remaining analysis after prune")
	}
}

func TestNotificationWebhook(t *testing.T) {
	got := make(chan map[string]any, 1)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p map[string]any
		json.NewDecoder(r.Body).Decode(&p)
		got <- p
		w.WriteHeader(http.StatusOK)
	}))
	defer hook.Close()

	srv := server.New(store.NewMemory())
	srv.SetWebhook(hook.URL)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	mustPost(t, ts.URL+"/api/v1/projects", map[string]string{"key": "demo"}, http.StatusCreated)
	rep, _ := scan.Scan(scan.Options{Root: "../../testdata/pyfixture"})
	var ignore map[string]any
	postJSON(t, ts.URL+"/api/v1/analyses?project=demo", rep, http.StatusCreated, &ignore)

	select {
	case p := <-got:
		if p["project"] != "demo" || p["gateStatus"] != gate.StatusError {
			t.Errorf("webhook payload = %+v, want project=demo gateStatus=ERROR", p)
		}
	default:
		t.Fatal("webhook was not called")
	}
}

func TestMeasuresHistory(t *testing.T) {
	ts := httptest.NewServer(server.New(store.NewMemory()))
	defer ts.Close()
	mustPost(t, ts.URL+"/api/v1/projects", map[string]string{"key": "demo"}, http.StatusCreated)

	rep, _ := scan.Scan(scan.Options{Root: "../../testdata/gofixture"})
	var ignore map[string]any
	for i := 0; i < 3; i++ {
		postJSON(t, ts.URL+"/api/v1/analyses?project=demo", rep, http.StatusCreated, &ignore)
	}

	var hist struct {
		Metric string `json:"metric"`
		Points []struct {
			AnalysisID string  `json:"analysisId"`
			Value      float64 `json:"value"`
		} `json:"points"`
	}
	getJSON(t, ts.URL+"/api/v1/measures/history?project=demo&metric=total_findings", http.StatusOK, &hist)
	if hist.Metric != "total_findings" {
		t.Errorf("metric = %q", hist.Metric)
	}
	if len(hist.Points) != 3 {
		t.Fatalf("history points = %d, want 3", len(hist.Points))
	}
	for _, p := range hist.Points {
		if p.Value != 4 {
			t.Errorf("point value = %v, want 4 (gofixture findings)", p.Value)
		}
	}
}

func TestConfigurableQualityGate(t *testing.T) {
	ts := httptest.NewServer(server.New(store.NewMemory()))
	defer ts.Close()
	mustPost(t, ts.URL+"/api/v1/projects", map[string]string{"key": "demo"}, http.StatusCreated)

	// default gate fails pyfixture (it has a vulnerability)
	rep, _ := scan.Scan(scan.Options{Root: "../../testdata/pyfixture"})
	var resp map[string]any
	postJSON(t, ts.URL+"/api/v1/analyses?project=demo", rep, http.StatusCreated, &resp)
	if g, _ := resp["gate"].(map[string]any); g["status"] != gate.StatusError {
		t.Fatalf("default gate should be ERROR, got %v", resp["gate"])
	}

	// create a lenient gate (only blockers fail) and assign it
	mustPost(t, ts.URL+"/api/v1/quality-gates", map[string]any{
		"id": "lenient", "name": "Lenient",
		"conditions": []map[string]any{{"metric": "blocker_issues", "op": "GT", "threshold": 0}},
	}, http.StatusCreated)
	postJSON(t, ts.URL+"/api/v1/projects/demo/quality-gate", map[string]string{"gateId": "lenient"}, http.StatusOK, nil)

	// now the same report passes (no blocker issues)
	postJSON(t, ts.URL+"/api/v1/analyses?project=demo", rep, http.StatusCreated, &resp)
	if g, _ := resp["gate"].(map[string]any); g["status"] != gate.StatusOK {
		t.Errorf("lenient gate should be OK, got %v", resp["gate"])
	}

	// the gate list includes default + lenient
	var gates []store.GateRecord
	getJSON(t, ts.URL+"/api/v1/quality-gates", http.StatusOK, &gates)
	if len(gates) != 2 {
		t.Errorf("gates = %d, want 2 (default + lenient)", len(gates))
	}
}

func TestAsyncIngest(t *testing.T) {
	srv := server.New(store.NewMemory())
	srv.EnableAsyncIngest(2)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	mustPost(t, ts.URL+"/api/v1/projects", map[string]string{"key": "demo"}, http.StatusCreated)
	rep, _ := scan.Scan(scan.Options{Root: "../../testdata/pyfixture"})

	// async ingest returns 202 + a task id
	var acc struct {
		TaskID string `json:"taskId"`
		Status string `json:"status"`
	}
	postJSON(t, ts.URL+"/api/v1/analyses?project=demo", rep, http.StatusAccepted, &acc)
	if acc.TaskID == "" || acc.Status != "queued" {
		t.Fatalf("async ingest = %+v, want a queued task", acc)
	}

	// poll the task to completion
	var task server.Task
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		getJSON(t, ts.URL+"/api/v1/tasks/"+acc.TaskID, http.StatusOK, &task)
		if task.Status == "done" || task.Status == "failed" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if task.Status != "done" {
		t.Fatalf("task status = %q, want done", task.Status)
	}
	if task.AnalysisID == "" || task.Gate.Status != gate.StatusError {
		t.Errorf("task result wrong: %+v", task)
	}

	// the analysis was persisted: issues are now queryable
	var issues []store.Issue
	getJSON(t, ts.URL+"/api/v1/issues?project=demo&open=true", http.StatusOK, &issues)
	if len(issues) != 4 {
		t.Errorf("open issues after async ingest = %d, want 4", len(issues))
	}
}

func TestRulesCatalog(t *testing.T) {
	ts := httptest.NewServer(server.New(store.NewMemory()))
	defer ts.Close()

	var all []rules.Meta
	getJSON(t, ts.URL+"/api/v1/rules", http.StatusOK, &all)
	if len(all) < 20 {
		t.Fatalf("rule catalog = %d, want many", len(all))
	}
	var eval *rules.Meta
	for i := range all {
		if all[i].ID == "py:exec-eval" {
			eval = &all[i]
		}
	}
	if eval == nil {
		t.Fatal("py:exec-eval missing from catalog")
	}
	if eval.Description == "" || len(eval.CWE) == 0 {
		t.Errorf("py:exec-eval lacks description/CWE: %+v", eval)
	}

	// language filter
	var goRules []rules.Meta
	getJSON(t, ts.URL+"/api/v1/rules?language=go", http.StatusOK, &goRules)
	if len(goRules) == 0 {
		t.Fatal("no go rules returned")
	}
	for _, m := range goRules {
		if m.Language != "go" {
			t.Errorf("filter leaked %s rule", m.Language)
		}
	}
}

func TestIngestUnknownProject(t *testing.T) {
	ts := httptest.NewServer(server.New(store.NewMemory()))
	defer ts.Close()
	postJSON(t, ts.URL+"/api/v1/analyses?project=nope", domain.Report{}, http.StatusNotFound, nil)
}

// --- helpers ---

func mustPost(t *testing.T, url string, body any, wantStatus int) {
	t.Helper()
	postJSON(t, url, body, wantStatus, nil)
}

func postJSON(t *testing.T, url string, body any, wantStatus int, out any) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST %s: status %d, want %d (%s)", url, resp.StatusCode, wantStatus, data)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode response: %v", err)
		}
	}
}

func getJSON(t *testing.T, url string, wantStatus int, out any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s: status %d, want %d (%s)", url, resp.StatusCode, wantStatus, data)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode response: %v", err)
		}
	}
}
