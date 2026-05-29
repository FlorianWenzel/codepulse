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

func TestJSRulesOnFixture(t *testing.T) {
	assertExact(t, runRules(t, lang.JavaScript, "../../testdata/jsfixture/sample.js"), map[string]int{
		"js:todo-comment":       1,
		"js:eval-usage":         1,
		"js:debugger-statement": 1,
		"js:child-process-exec": 1,
		"js:high-complexity":    1,
	})
}

func TestTSRulesOnFixture(t *testing.T) {
	assertExact(t, runRules(t, lang.TypeScript, "../../testdata/tsfixture/sample.ts"), map[string]int{
		"ts:todo-comment":    1,
		"ts:eval-usage":      1,
		"ts:high-complexity": 1,
	})
}

func TestJavaRulesOnFixture(t *testing.T) {
	assertExact(t, runRules(t, lang.Java, "../../testdata/javafixture/Sample.java"), map[string]int{
		"java:todo-comment":    1,
		"java:empty-catch":     1,
		"java:catch-generic":   1, // catch (Exception e) is both empty and overly broad
		"java:system-exit":     1,
		"java:high-complexity": 1,
	})
}

func TestRubyRulesOnFixture(t *testing.T) {
	assertExact(t, runRules(t, lang.Ruby, "../../testdata/rubyfixture/sample.rb"), map[string]int{
		"ruby:todo-comment":    1,
		"ruby:high-complexity": 1,
	})
}

func TestRustRulesOnFixture(t *testing.T) {
	assertExact(t, runRules(t, lang.Rust, "../../testdata/rustfixture/sample.rs"), map[string]int{
		"rust:todo-comment":    1,
		"rust:high-complexity": 1,
		"rust:unwrap":          1,
	})
}

func TestCRulesOnFixture(t *testing.T) {
	assertExact(t, runRules(t, lang.C, "../../testdata/cfixture/sample.c"), map[string]int{
		"c:todo-comment":    1,
		"c:high-complexity": 1,
	})
}

func TestBashRulesOnFixture(t *testing.T) {
	assertExact(t, runRules(t, lang.Bash, "../../testdata/bashfixture/sample.sh"), map[string]int{
		"bash:todo-comment":    1,
		"bash:high-complexity": 1,
	})
}

func TestMoreLanguageRules(t *testing.T) {
	cases := []struct {
		l       lang.Language
		fixture string
		todo    string
		cx      string
	}{
		{lang.Cpp, "../../testdata/cppfixture/sample.cpp", "cpp:todo-comment", "cpp:high-complexity"},
		{lang.CSharp, "../../testdata/csfixture/Sample.cs", "cs:todo-comment", "cs:high-complexity"},
		{lang.PHP, "../../testdata/phpfixture/sample.php", "php:todo-comment", "php:high-complexity"},
		{lang.Kotlin, "../../testdata/ktfixture/sample.kt", "kt:todo-comment", "kt:high-complexity"},
		{lang.Scala, "../../testdata/scalafixture/sample.scala", "scala:todo-comment", "scala:high-complexity"},
		{lang.Swift, "../../testdata/swiftfixture/sample.swift", "swift:todo-comment", "swift:high-complexity"},
	}
	for _, c := range cases {
		t.Run(string(c.l), func(t *testing.T) {
			assertExact(t, runRules(t, c.l, c.fixture), map[string]int{c.todo: 1, c.cx: 1})
		})
	}
}

// runRulesSrc runs the rules for a language over inline source.
func runRulesSrc(t *testing.T, l lang.Language, src string) map[string]int {
	t.Helper()
	spec, ok := langspec.For(l)
	if !ok {
		t.Fatalf("no spec for %s", l)
	}
	tree, err := parse.Parse(spec.TS, []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	eng, err := rules.NewEngine(spec.TS, rules.ForLanguage(l))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	counts := map[string]int{}
	for _, f := range eng.Run("x", tree.RootNode(), []byte(src)) {
		counts[f.RuleID]++
	}
	return counts
}

func TestDebugLeftoverRules(t *testing.T) {
	cases := []struct {
		l    lang.Language
		src  string
		rule string
	}{
		{lang.Go, "package p\nimport \"fmt\"\nfunc f() { fmt.Println(\"x\") }\n", "go:debug-print"},
		{lang.Python, "print('x')\n", "py:debug-print"},
		{lang.JavaScript, "console.log('x');\n", "js:console-usage"},
		{lang.Java, "class C { void m(Exception e) { e.printStackTrace(); } }\n", "java:print-stacktrace"},
	}
	for _, c := range cases {
		t.Run(c.rule, func(t *testing.T) {
			if got := runRulesSrc(t, c.l, c.src)[c.rule]; got != 1 {
				t.Errorf("%s fired %d times, want 1", c.rule, got)
			}
		})
	}
}

func TestSecurityRules(t *testing.T) {
	cases := []struct {
		l    lang.Language
		src  string
		rule string
	}{
		{lang.Python, "import yaml\nx = yaml.load(s)\n", "py:yaml-unsafe-load"},
		{lang.Python, "import pickle\nx = pickle.loads(b)\n", "py:pickle-load"},
		{lang.Go, "package p\nimport \"crypto/md5\"\nfunc f() { _ = md5.New() }\n", "go:weak-hash"},
		{lang.JavaScript, "el.innerHTML = userInput;\n", "js:inner-html"},
	}
	for _, c := range cases {
		t.Run(c.rule, func(t *testing.T) {
			if got := runRulesSrc(t, c.l, c.src)[c.rule]; got != 1 {
				t.Errorf("%s fired %d times, want 1", c.rule, got)
			}
		})
	}
}

func TestExpandedRules(t *testing.T) {
	cases := []struct {
		l    lang.Language
		src  string
		rule string
	}{
		{lang.Go, "package p\nimport \"context\"\nfunc f() { _ = context.TODO() }\n", "go:context-todo"},
		{lang.Go, "package p\nimport (\"errors\"; \"fmt\")\nfunc f() error { return errors.New(fmt.Sprintf(\"x %d\", 1)) }\n", "go:error-new-fmt"},
		{lang.JavaScript, "const ok = (a == b);\n", "js:loose-equality"},
		{lang.JavaScript, "var x = 1;\n", "js:var-declaration"},
		{lang.TypeScript, "const ok = (a == b);\n", "ts:loose-equality"},
		{lang.Java, "class C { void m() { System.out.println(\"x\"); } }\n", "java:system-print"},
		{lang.Java, "class C { void m() { try { x(); } catch (Throwable t) { handle(); } } }\n", "java:catch-generic"},
	}
	for _, c := range cases {
		t.Run(c.rule, func(t *testing.T) {
			if got := runRulesSrc(t, c.l, c.src)[c.rule]; got != 1 {
				t.Errorf("%s fired %d times, want 1", c.rule, got)
			}
		})
	}
}

func TestExpandedRules2(t *testing.T) {
	cases := []struct {
		l    lang.Language
		src  string
		rule string
	}{
		{lang.Go, "package p\nimport \"os\"\nfunc f() { os.Exit(1) }\n", "go:os-exit"},
		{lang.JavaScript, "document.write(userInput);\n", "js:document-write"},
		{lang.JavaScript, "alert('hi');\n", "js:alert"},
		{lang.TypeScript, "document.write(x);\n", "ts:document-write"},
		{lang.Java, "class C { void m(int x) { assert x > 0; } }\n", "java:assert-usage"},
	}
	for _, c := range cases {
		t.Run(c.rule, func(t *testing.T) {
			if got := runRulesSrc(t, c.l, c.src)[c.rule]; got != 1 {
				t.Errorf("%s fired %d times, want 1", c.rule, got)
			}
		})
	}
}

func TestExpandedRules3(t *testing.T) {
	cases := []struct {
		l    lang.Language
		src  string
		rule string
	}{
		{lang.Go, "package p\nimport \"io/ioutil\"\nfunc f() { _, _ = ioutil.ReadFile(\"x\") }\n", "go:ioutil-deprecated"},
		{lang.JavaScript, "function f() { throw 'boom'; }\n", "js:throw-literal"},
		{lang.TypeScript, "function f() { throw 'boom'; }\n", "ts:throw-literal"},
		{lang.Java, "class C { void m() throws Exception { Thread.sleep(100); } }\n", "java:thread-sleep"},
	}
	for _, c := range cases {
		t.Run(c.rule, func(t *testing.T) {
			if got := runRulesSrc(t, c.l, c.src)[c.rule]; got != 1 {
				t.Errorf("%s fired %d times, want 1", c.rule, got)
			}
		})
	}
}

func TestExpandedRules4(t *testing.T) {
	cases := []struct {
		l    lang.Language
		src  string
		rule string
	}{
		{lang.Python, "def f():\n    assert (1, \"oops\")\n", "py:assert-tuple"},
		{lang.Python, "def f(x=[]):\n    return x\n", "py:mutable-default-arg"},
		{lang.JavaScript, "function f(o) { with (o) { y = 1; } }\n", "js:no-with"},
		{lang.TypeScript, "function f(o: any) { with (o) { } }\n", "ts:no-with"},
	}
	for _, c := range cases {
		t.Run(c.rule, func(t *testing.T) {
			if got := runRulesSrc(t, c.l, c.src)[c.rule]; got != 1 {
				t.Errorf("%s fired %d times, want 1", c.rule, got)
			}
		})
	}
}

func TestExpandedRules5(t *testing.T) {
	cases := []struct {
		l    lang.Language
		src  string
		rule string
	}{
		{lang.JavaScript, "const s = new String('x');\n", "js:no-new-wrappers"},
		{lang.TypeScript, "const s = new Number(1);\n", "ts:no-new-wrappers"},
		{lang.Java, "import java.util.*;\nclass C { Object m() { return new Vector(); } }\n", "java:legacy-collection"},
		{lang.Python, "from os import *\n", "py:wildcard-import"},
	}
	for _, c := range cases {
		t.Run(c.rule, func(t *testing.T) {
			if got := runRulesSrc(t, c.l, c.src)[c.rule]; got != 1 {
				t.Errorf("%s fired %d times, want 1", c.rule, got)
			}
		})
	}
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
