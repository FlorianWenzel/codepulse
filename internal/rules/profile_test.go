package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/lang"
	"github.com/FlorianWenzel/codepulse/internal/langspec"
)

func TestProfileApply(t *testing.T) {
	base := []Rule{
		{ID: "go:panic-usage", Severity: domain.SevMajor},
		{ID: "go:todo-comment", Severity: domain.SevInfo},
		{ID: "go:empty-block", Severity: domain.SevMinor},
	}
	p := &Profile{
		Disable:  []string{"go:todo-comment"},
		Severity: map[string]string{"go:panic-usage": "BLOCKER"},
	}
	out := p.Apply(base)
	if len(out) != 2 {
		t.Fatalf("applied rules = %d, want 2 (one disabled)", len(out))
	}
	for _, r := range out {
		if r.ID == "go:todo-comment" {
			t.Error("go:todo-comment should have been disabled")
		}
		if r.ID == "go:panic-usage" && r.Severity != domain.SevBlocker {
			t.Errorf("go:panic-usage severity = %q, want BLOCKER", r.Severity)
		}
	}
	// Apply must not mutate the input slice's rules.
	if base[0].Severity != domain.SevMajor {
		t.Error("Apply mutated the input rule severity")
	}
}

func TestProfileApplyToComplexityThreshold(t *testing.T) {
	spec := langspec.Go()
	base := ForLanguage(lang.Go)
	p := &Profile{ComplexityThreshold: 42}
	out := p.ApplyTo(spec, base)

	// The high-complexity rule must be present and rebuilt; the others intact.
	if len(out) != len(base) {
		t.Errorf("rule count changed: got %d, want %d", len(out), len(base))
	}
	var found bool
	for _, r := range out {
		if r.ID == "go:high-complexity" {
			found = true
			if r.Visit == nil {
				t.Error("rebuilt complexity rule lost its Visit func")
			}
		}
	}
	if !found {
		t.Error("go:high-complexity missing after ApplyTo")
	}
}

func TestProfileApplyNil(t *testing.T) {
	base := []Rule{{ID: "x"}}
	var p *Profile
	if got := p.Apply(base); len(got) != 1 {
		t.Errorf("nil profile should be a no-op, got %d rules", len(got))
	}
}

func TestLoadProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yml")
	if err := os.WriteFile(path, []byte("disable:\n  - go:panic-usage\nseverity:\n  py:bare-except: MINOR\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := LoadProfile(path)
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}
	if len(p.Disable) != 1 || p.Disable[0] != "go:panic-usage" {
		t.Errorf("disable = %v", p.Disable)
	}
	if p.Severity["py:bare-except"] != "MINOR" {
		t.Errorf("severity override not parsed: %v", p.Severity)
	}
}

func TestLoadProfileRejectsBadRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yml")
	os.WriteFile(path, []byte("disable: [go:does-not-exist]\n"), 0o644)
	if _, err := LoadProfile(path); err == nil {
		t.Error("expected error for unknown rule id")
	}
}

func TestLoadProfileRejectsBadSeverity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yml")
	os.WriteFile(path, []byte("severity:\n  go:panic-usage: SOMETIMES\n"), 0o644)
	if _, err := LoadProfile(path); err == nil {
		t.Error("expected error for invalid severity")
	}
}
