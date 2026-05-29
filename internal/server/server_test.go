package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/scan"
	"github.com/FlorianWenzel/codepulse/internal/server"
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
