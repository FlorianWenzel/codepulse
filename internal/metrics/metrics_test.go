package metrics_test

import (
	"testing"

	"github.com/FlorianWenzel/codepulse/internal/lang"
	"github.com/FlorianWenzel/codepulse/internal/langspec"
	"github.com/FlorianWenzel/codepulse/internal/metrics"
	"github.com/FlorianWenzel/codepulse/internal/parse"
)

func goSpec(t *testing.T) langspec.Spec {
	t.Helper()
	s, ok := langspec.For(lang.Go)
	if !ok {
		t.Fatal("no go spec")
	}
	return s
}

func TestCyclomaticComplexity(t *testing.T) {
	// f: base 1 + if(1) + &&(1) + for(1) = 4
	src := []byte("package p\nfunc f(x int) int {\n\tif x > 0 && x < 10 {\n\t\treturn 1\n\t}\n\tfor i := 0; i < x; i++ {\n\t}\n\treturn 0\n}\n")
	spec := goSpec(t)
	tree, err := parse.Parse(spec.TS, src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fns := metrics.Functions(spec, tree.RootNode(), src)
	if len(fns) != 1 {
		t.Fatalf("got %d functions, want 1", len(fns))
	}
	if fns[0].Name != "f" {
		t.Errorf("func name = %q, want f", fns[0].Name)
	}
	if fns[0].Complexity != 4 {
		t.Errorf("cyclomatic = %d, want 4", fns[0].Complexity)
	}
}

func TestSizeMetrics(t *testing.T) {
	src := []byte("package p\n\n// a comment\nfunc f() {\n\treturn\n}\n")
	spec := goSpec(t)
	tree, err := parse.Parse(spec.TS, src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m := metrics.Compute(spec, "x.go", tree.RootNode(), src)
	if m.Functions != 1 {
		t.Errorf("functions = %d, want 1", m.Functions)
	}
	if m.CommentLines != 1 {
		t.Errorf("commentLines = %d, want 1", m.CommentLines)
	}
	// code lines: package, func, return, closing brace = 4
	if m.Ncloc != 4 {
		t.Errorf("ncloc = %d, want 4", m.Ncloc)
	}
}

func TestPythonComplexity(t *testing.T) {
	// f: base 1 + if(1) + and(1) = 3 ; while(1) => 4
	src := []byte("def f(x):\n    if x > 0 and x < 10:\n        return 1\n    while x:\n        x -= 1\n    return 0\n")
	spec, _ := langspec.For(lang.Python)
	tree, err := parse.Parse(spec.TS, src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fns := metrics.Functions(spec, tree.RootNode(), src)
	if len(fns) != 1 {
		t.Fatalf("got %d python functions, want 1", len(fns))
	}
	if fns[0].Complexity != 4 {
		t.Errorf("python cyclomatic = %d, want 4", fns[0].Complexity)
	}
}
