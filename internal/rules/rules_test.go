package rules_test

import (
	"os"
	"testing"

	"github.com/FlorianWenzel/codepulse/internal/lang"
	"github.com/FlorianWenzel/codepulse/internal/langspec"
	"github.com/FlorianWenzel/codepulse/internal/parse"
	"github.com/FlorianWenzel/codepulse/internal/rules"
)

// runRules parses a fixture and returns rule-id -> finding count.
func runRules(t *testing.T, l lang.Language, fixture string) map[string]int {
	t.Helper()
	src, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	spec, ok := langspec.For(l)
	if !ok {
		t.Fatalf("no spec for %s", l)
	}
	tree, err := parse.Parse(spec.TS, src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	eng, err := rules.NewEngine(spec.TS, rules.ForLanguage(l))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	counts := map[string]int{}
	for _, f := range eng.Run(fixture, tree.RootNode(), src) {
		counts[f.RuleID]++
	}
	return counts
}

// assertExact checks counts match want exactly (no misses, no false positives).
func assertExact(t *testing.T, counts, want map[string]int) {
	t.Helper()
	for id, n := range want {
		if counts[id] != n {
			t.Errorf("rule %s: got %d findings, want %d", id, counts[id], n)
		}
	}
	for id := range counts {
		if _, ok := want[id]; !ok {
			t.Errorf("unexpected rule fired: %s (%d)", id, counts[id])
		}
	}
}

func TestGoRulesOnFixture(t *testing.T) {
	assertExact(t, runRules(t, lang.Go, "../../testdata/gofixture/sample.go"), map[string]int{
		"go:panic-usage":     1,
		"go:todo-comment":    1,
		"go:empty-block":     1,
		"go:high-complexity": 1,
	})
}

func TestPythonRulesOnFixture(t *testing.T) {
	assertExact(t, runRules(t, lang.Python, "../../testdata/pyfixture/sample.py"), map[string]int{
		"py:exec-eval":       1,
		"py:todo-comment":    1,
		"py:bare-except":     1,
		"py:high-complexity": 1,
	})
}

// TestBadQueryFailsLoudly ensures an invalid query is reported at engine
// construction rather than silently skipped.
func TestBadQueryFailsLoudly(t *testing.T) {
	spec, _ := langspec.For(lang.Go)
	_, err := rules.NewEngine(spec.TS, []rules.Rule{{
		ID: "go:broken", Query: "(this is not valid", Capture: "flag",
	}})
	if err == nil {
		t.Fatal("expected error for invalid query, got nil")
	}
}
