package rules_test

import (
	"os"
	"testing"

	"github.com/FlorianWenzel/codepulse/internal/parse"
	"github.com/FlorianWenzel/codepulse/internal/rules"
)

// TestGoRulesOnFixture asserts each built-in rule fires exactly the expected
// number of times on the fixture — guarding against both misses and false
// positives.
func TestGoRulesOnFixture(t *testing.T) {
	src, err := os.ReadFile("../../testdata/gofixture/sample.go")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	tree, err := parse.Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	eng, err := rules.NewEngine(parse.GoLanguage(), rules.GoRules())
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	counts := map[string]int{}
	for _, f := range eng.Run("sample.go", tree.RootNode(), src) {
		counts[f.RuleID]++
	}

	want := map[string]int{
		"go:panic-usage":    1,
		"go:todo-comment":   1,
		"go:empty-block":    1,
		"go:high-complexity": 1,
	}
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

// TestBadQueryFailsLoudly ensures an invalid query is reported at engine
// construction rather than silently skipped.
func TestBadQueryFailsLoudly(t *testing.T) {
	_, err := rules.NewEngine(parse.GoLanguage(), []rules.Rule{{
		ID: "go:broken", Query: "(this is not valid", Capture: "flag",
	}})
	if err == nil {
		t.Fatal("expected error for invalid query, got nil")
	}
}
