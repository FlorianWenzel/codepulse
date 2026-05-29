package decorate_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/FlorianWenzel/codepulse/internal/server/decorate"
)

func TestGitHubDecorate(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	gh := &decorate.GitHub{BaseURL: srv.URL, Token: "tok123"}
	err := gh.Decorate(context.Background(), decorate.Status{
		Repo: "acme/widgets", Commit: "deadbeef", GateOK: false, Description: "gate: ERROR",
	})
	if err != nil {
		t.Fatalf("decorate: %v", err)
	}
	if gotPath != "/repos/acme/widgets/statuses/deadbeef" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer tok123" {
		t.Errorf("auth = %q", gotAuth)
	}
	if gotBody["state"] != "failure" {
		t.Errorf("state = %q, want failure", gotBody["state"])
	}
	if gotBody["context"] != "codepulse" {
		t.Errorf("context = %q", gotBody["context"])
	}
}

func TestGitHubDecorateSuccess(t *testing.T) {
	var state string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &b)
		state = b["state"]
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	gh := &decorate.GitHub{BaseURL: srv.URL}
	if err := gh.Decorate(context.Background(), decorate.Status{Repo: "a/b", Commit: "c", GateOK: true}); err != nil {
		t.Fatal(err)
	}
	if state != "success" {
		t.Errorf("state = %q, want success", state)
	}
}

func TestGitHubDecorateServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	gh := &decorate.GitHub{BaseURL: srv.URL}
	if err := gh.Decorate(context.Background(), decorate.Status{Repo: "a/b", Commit: "c"}); err == nil {
		t.Error("expected error on 500 response")
	}
}
