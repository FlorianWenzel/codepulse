package scan_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/FlorianWenzel/codepulse/internal/scan"
)

// gitRepo initializes a throwaway git repo at dir.
func gitRepo(t *testing.T, dir string) {
	t.Helper()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")
}

// commit writes a file and commits it with a specific author/committer date.
func commit(t *testing.T, dir, name, content, date string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", name}, {"commit", "-q", "-m", "add " + name}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
			"GIT_AUTHOR_DATE="+date, "GIT_COMMITTER_DATE="+date)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

// TestNewCodePeriod scans a real git repo: an old file (committed long ago)
// and a new file (committed today). With a 30-day new-code window, only the
// new file's findings should be flagged new, and blame author is attributed.
func TestNewCodePeriod(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	gitRepo(t, dir)

	// Each file has exactly one finding: a panic() (go:panic-usage).
	oldSrc := "package x\nfunc Old() { panic(\"old\") }\n"
	newSrc := "package x\nfunc New() { panic(\"new\") }\n"
	commit(t, dir, "old.go", oldSrc, "2020-01-01T00:00:00")
	commit(t, dir, "new.go", newSrc, "") // empty date => now

	rep, err := scan.Scan(scan.Options{Root: dir, NewCodeDays: 30})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Summary.TotalFindings != 2 {
		t.Fatalf("findings = %d, want 2", rep.Summary.TotalFindings)
	}
	if rep.Summary.NewFindings != 1 {
		t.Errorf("new findings = %d, want 1 (only new.go)", rep.Summary.NewFindings)
	}

	var newOnes, oldOnes int
	for _, f := range rep.Findings {
		if f.Author == "" {
			t.Errorf("finding in %s has no blame author", f.Location.File)
		}
		if f.IsNew {
			newOnes++
			if f.Location.File != "new.go" {
				t.Errorf("unexpected new finding in %s", f.Location.File)
			}
		} else {
			oldOnes++
		}
	}
	if newOnes != 1 || oldOnes != 1 {
		t.Errorf("new/old split = %d/%d, want 1/1", newOnes, oldOnes)
	}
}

// TestNewCodeDisabled: without a window, nothing is attributed/new.
func TestNewCodeDisabled(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/gofixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Summary.NewFindings != 0 {
		t.Errorf("new findings = %d, want 0 when new-code disabled", rep.Summary.NewFindings)
	}
}
