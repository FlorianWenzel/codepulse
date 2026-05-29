// Package decorate posts CodePulse quality-gate results back to a source host
// (e.g. GitHub commit statuses) so they appear on pull requests.
package decorate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Status is the gate outcome to report for a commit.
type Status struct {
	Repo        string // "owner/name"
	Commit      string // SHA
	GateOK      bool
	Description string
	TargetURL   string
}

// Decorator posts a status to a source host.
type Decorator interface {
	Decorate(ctx context.Context, s Status) error
}

// GitHub posts commit statuses via the GitHub REST API. BaseURL defaults to
// the public API; tests point it at an httptest server.
type GitHub struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// Decorate posts a commit status (success/failure) for s.Commit.
func (g *GitHub) Decorate(ctx context.Context, s Status) error {
	base := g.BaseURL
	if base == "" {
		base = "https://api.github.com"
	}
	state := "failure"
	if s.GateOK {
		state = "success"
	}
	payload, _ := json.Marshal(map[string]string{
		"state":       state,
		"context":     "codepulse",
		"description": s.Description,
		"target_url":  s.TargetURL,
	})
	url := fmt.Sprintf("%s/repos/%s/statuses/%s", base, s.Repo, s.Commit)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	client := g.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("github decoration failed: %s", resp.Status)
	}
	return nil
}
