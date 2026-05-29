package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/server"
	"github.com/FlorianWenzel/codepulse/internal/server/store"
)

// authReq issues an HTTP request with an optional bearer token.
func authReq(t *testing.T, baseURL, method, path, token string, body any) *http.Response {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, baseURL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestAuthAndRBAC(t *testing.T) {
	srv := server.New(store.NewMemory())
	if err := srv.BootstrapAdmin("admintok"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// no token -> 401
	if r := authReq(t, ts.URL, "POST", "/api/v1/projects", "", map[string]string{"key": "demo"}); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("create project without token = %d, want 401", r.StatusCode)
	}
	// wrong token -> 401
	if r := authReq(t, ts.URL, "GET", "/api/v1/projects", "bogus", nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bogus token = %d, want 401", r.StatusCode)
	}
	// admin creates two projects
	for _, k := range []string{"demo", "other"} {
		if r := authReq(t, ts.URL, "POST", "/api/v1/projects", "admintok", map[string]string{"key": k}); r.StatusCode != http.StatusCreated {
			t.Fatalf("admin create %s = %d, want 201", k, r.StatusCode)
		}
	}

	// admin mints a project-scoped scan token for demo
	r := authReq(t, ts.URL, "POST", "/api/v1/tokens", "admintok",
		map[string]string{"name": "ci", "role": "scan", "project": "demo"})
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("create token = %d, want 201", r.StatusCode)
	}
	var tok struct {
		Token string `json:"token"`
	}
	json.NewDecoder(r.Body).Decode(&tok)
	if tok.Token == "" {
		t.Fatal("no token secret returned")
	}

	// a non-admin (scan) token cannot create projects
	if r := authReq(t, ts.URL, "POST", "/api/v1/projects", tok.Token, map[string]string{"key": "x"}); r.StatusCode != http.StatusForbidden {
		t.Errorf("scan token create project = %d, want 403", r.StatusCode)
	}

	// scan token can ingest its own project...
	if r := authReq(t, ts.URL, "POST", "/api/v1/analyses?project=demo", tok.Token, domain.Report{}); r.StatusCode != http.StatusCreated {
		t.Errorf("scan ingest demo = %d, want 201", r.StatusCode)
	}
	// ...but not a different project
	if r := authReq(t, ts.URL, "POST", "/api/v1/analyses?project=other", tok.Token, domain.Report{}); r.StatusCode != http.StatusForbidden {
		t.Errorf("scan ingest other = %d, want 403", r.StatusCode)
	}

	// scan token can read its project; anonymous cannot
	if r := authReq(t, ts.URL, "GET", "/api/v1/issues?project=demo", tok.Token, nil); r.StatusCode != http.StatusOK {
		t.Errorf("scan read demo issues = %d, want 200", r.StatusCode)
	}
	if r := authReq(t, ts.URL, "GET", "/api/v1/issues?project=demo", "", nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous read = %d, want 401", r.StatusCode)
	}
	// scan token cannot triage (admin-only)
	if r := authReq(t, ts.URL, "POST", "/api/v1/issues/transition", tok.Token,
		map[string]string{"project": "demo", "key": "k", "transition": "confirm"}); r.StatusCode != http.StatusForbidden {
		t.Errorf("scan triage = %d, want 403", r.StatusCode)
	}
}
