package scan_test

import (
	"testing"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/rules"
	"github.com/FlorianWenzel/codepulse/internal/scan"
)

// TestScanFixtureDir is an end-to-end test of the scan pipeline over a real
// directory: walk → parse → rules → metrics → aggregated report.
func TestScanFixtureDir(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/gofixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Summary.FilesAnalyzed != 1 {
		t.Errorf("files analyzed = %d, want 1", rep.Summary.FilesAnalyzed)
	}
	if rep.Summary.TotalFindings != 4 {
		t.Errorf("total findings = %d, want 4", rep.Summary.TotalFindings)
	}
	if rep.Summary.TotalNcloc == 0 {
		t.Error("expected non-zero ncloc")
	}
	if rep.Summary.ByType[domain.TypeCodeSmell] != 4 {
		t.Errorf("code smells = %d, want 4", rep.Summary.ByType[domain.TypeCodeSmell])
	}

	// findings must be deterministically ordered by line.
	for i := 1; i < len(rep.Findings); i++ {
		a, b := rep.Findings[i-1], rep.Findings[i]
		if a.Location.File == b.Location.File && a.Location.StartLine > b.Location.StartLine {
			t.Errorf("findings not ordered by line: %d before %d", a.Location.StartLine, b.Location.StartLine)
		}
	}
}

func TestScanRelativePaths(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/gofixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, m := range rep.Metrics {
		if m.Path != "sample.go" {
			t.Errorf("metric path = %q, want project-relative sample.go", m.Path)
		}
	}
}

func TestScanPythonFixtureDir(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/pyfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Summary.FilesAnalyzed != 1 {
		t.Errorf("files analyzed = %d, want 1", rep.Summary.FilesAnalyzed)
	}
	if rep.Summary.TotalFindings != 4 {
		t.Errorf("total findings = %d, want 4", rep.Summary.TotalFindings)
	}
	if rep.Language != "python" {
		t.Errorf("language = %q, want python", rep.Language)
	}
	// one of the python findings is a VULNERABILITY (eval/exec)
	if rep.Summary.ByType[domain.TypeVulnerability] != 1 {
		t.Errorf("vulnerabilities = %d, want 1", rep.Summary.ByType[domain.TypeVulnerability])
	}
}

func TestScanRatings(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/pyfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	// pyfixture has a CRITICAL vulnerability (eval) and a MAJOR bug (bare-except).
	if rep.Summary.Ratings.Security != domain.RatingD {
		t.Errorf("security rating = %s, want D (critical vuln)", rep.Summary.Ratings.Security)
	}
	if rep.Summary.Ratings.Reliability != domain.RatingC {
		t.Errorf("reliability rating = %s, want C (major bug)", rep.Summary.Ratings.Reliability)
	}
	if rep.Summary.Ratings.Maintainability == "" {
		t.Error("maintainability rating should be set")
	}
	if rep.Summary.Ratings.TechDebtMin <= 0 {
		t.Error("expected positive technical debt from code smells")
	}
}

func TestScanJavaScript(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/jsfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Language != "javascript" {
		t.Errorf("language = %q, want javascript", rep.Language)
	}
	if rep.Summary.TotalFindings != 5 {
		t.Errorf("findings = %d, want 5", rep.Summary.TotalFindings)
	}
	if rep.Summary.ByType[domain.TypeHotspot] != 1 {
		t.Errorf("security hotspots = %d, want 1 (child-process exec)", rep.Summary.ByType[domain.TypeHotspot])
	}
	if rep.Summary.ByType[domain.TypeVulnerability] != 1 {
		t.Errorf("vulnerabilities = %d, want 1 (eval)", rep.Summary.ByType[domain.TypeVulnerability])
	}
}

func TestScanJava(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/javafixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Language != "java" {
		t.Errorf("language = %q, want java", rep.Language)
	}
	// todo, empty-catch (bug), catch-generic (smell), system-exit, high-complexity
	if rep.Summary.TotalFindings != 5 {
		t.Errorf("findings = %d, want 5", rep.Summary.TotalFindings)
	}
	if rep.Summary.ByType[domain.TypeBug] != 1 {
		t.Errorf("bugs = %d, want 1 (empty catch)", rep.Summary.ByType[domain.TypeBug])
	}
}

// TestScanGoBugRules covers the bug/hotspot rules that need AST context:
// defer-in-loop (not the closure variant), discarded append, and TLS
// InsecureSkipVerify.
func TestScanGoBugRules(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/gobugfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	want := map[string]bool{
		"go:defer-in-loop":            false,
		"go:discarded-append":         false,
		"go:tls-insecure-skip-verify": false,
	}
	for _, f := range rep.Findings {
		if _, ok := want[f.RuleID]; ok {
			want[f.RuleID] = true
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("expected rule %s to fire on gobugfixture", id)
		}
	}
	// The defer inside a per-iteration closure must NOT be flagged.
	if n := countRule(rep, "go:defer-in-loop"); n != 1 {
		t.Errorf("go:defer-in-loop fired %d times, want 1 (closure variant excluded)", n)
	}
}

// TestScanJavaBugRules covers Java rules added beyond the starter set:
// reference-equality string compare, catching NPE, and hard-coded credentials.
func TestScanJavaBugRules(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/javabugfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, id := range []string{"java:string-eq-ref", "java:catch-npe", "java:hardcoded-credentials"} {
		if countRule(rep, id) != 1 {
			t.Errorf("expected rule %s to fire exactly once, got %d", id, countRule(rep, id))
		}
	}
	// The catch block here is non-empty, so empty-catch must not fire.
	if countRule(rep, "java:empty-catch") != 0 {
		t.Errorf("java:empty-catch should not fire on a non-empty catch")
	}
}

// TestScanJSBugRules covers the JS/TS rules added beyond the starter set:
// implied eval (string setTimeout), empty catch, and hard-coded credentials.
// The fixture has one .js and one .ts file to exercise both prefixes.
func TestScanJSBugRules(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/jsbugfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, id := range []string{"js:implied-eval", "js:empty-catch", "js:hardcoded-credentials", "ts:hardcoded-credentials"} {
		if countRule(rep, id) != 1 {
			t.Errorf("expected rule %s to fire exactly once, got %d", id, countRule(rep, id))
		}
	}
	// setInterval with a function reference must NOT be flagged as implied-eval.
	if countRule(rep, "js:implied-eval") != 1 {
		t.Errorf("implied-eval should fire only for the string argument, got %d", countRule(rep, "js:implied-eval"))
	}
}

// TestScanPythonSecurityRules covers the Python security hotspots added beyond
// the starter set: subprocess shell=True, weak hash, requests verify=False, and
// hard-coded credentials.
func TestScanPythonSecurityRules(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/pybugfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, id := range []string{"py:subprocess-shell", "py:weak-hash", "py:requests-no-verify", "py:hardcoded-credentials"} {
		if countRule(rep, id) != 1 {
			t.Errorf("expected rule %s to fire exactly once, got %d", id, countRule(rep, id))
		}
	}
}

// TestScanPHPSecurityRules covers the PHP security rules (eval, shell exec,
// weak hash) added on top of the todo/complexity starter set.
func TestScanPHPSecurityRules(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/phpbugfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Language != "php" {
		t.Errorf("language = %q, want php", rep.Language)
	}
	for _, id := range []string{"php:eval-usage", "php:exec-usage", "php:weak-hash"} {
		if countRule(rep, id) != 1 {
			t.Errorf("expected rule %s to fire exactly once, got %d", id, countRule(rep, id))
		}
	}
	// eval + exec are vulnerabilities
	if rep.Summary.ByType[domain.TypeVulnerability] != 2 {
		t.Errorf("vulnerabilities = %d, want 2", rep.Summary.ByType[domain.TypeVulnerability])
	}
}

// TestScanRubySecurityRules covers the Ruby security rules (eval, command exec,
// weak hash) added on top of the todo/complexity starter set.
func TestScanRubySecurityRules(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/rubybugfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Language != "ruby" {
		t.Errorf("language = %q, want ruby", rep.Language)
	}
	for _, id := range []string{"ruby:eval-usage", "ruby:command-exec", "ruby:weak-hash"} {
		if countRule(rep, id) != 1 {
			t.Errorf("expected rule %s to fire exactly once, got %d", id, countRule(rep, id))
		}
	}
	if rep.Summary.ByType[domain.TypeVulnerability] != 2 {
		t.Errorf("vulnerabilities = %d, want 2 (eval + command-exec)", rep.Summary.ByType[domain.TypeVulnerability])
	}
}

// TestScanCFamilySecurityRules covers the C/C++ memory-safety + exec rules.
// The fixture has a .c and a .cpp file to exercise both prefixes.
func TestScanCFamilySecurityRules(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/cbugfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, id := range []string{"c:unsafe-cstring-fn", "c:system-exec", "cpp:unsafe-cstring-fn"} {
		if countRule(rep, id) != 1 {
			t.Errorf("expected rule %s to fire exactly once, got %d", id, countRule(rep, id))
		}
	}
}

// TestScanCSharpSecurityRules covers the C# rules (empty catch, weak hash,
// Process.Start) added on top of the todo/complexity starter set.
func TestScanCSharpSecurityRules(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/csbugfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Language != "csharp" {
		t.Errorf("language = %q, want csharp", rep.Language)
	}
	for _, id := range []string{"cs:empty-catch", "cs:weak-hash", "cs:process-start"} {
		if countRule(rep, id) != 1 {
			t.Errorf("expected rule %s to fire exactly once, got %d", id, countRule(rep, id))
		}
	}
}

// TestScanBashSecurityRules covers the Bash security rules (eval, curl|shell)
// added on top of the todo/complexity starter set.
func TestScanBashSecurityRules(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/bashbugfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Language != "bash" {
		t.Errorf("language = %q, want bash", rep.Language)
	}
	for _, id := range []string{"bash:eval-usage", "bash:curl-pipe-shell"} {
		if countRule(rep, id) != 1 {
			t.Errorf("expected rule %s to fire exactly once, got %d", id, countRule(rep, id))
		}
	}
	if rep.Summary.ByType[domain.TypeVulnerability] != 2 {
		t.Errorf("vulnerabilities = %d, want 2", rep.Summary.ByType[domain.TypeVulnerability])
	}
}

// TestScanKotlinRules covers the Kotlin rules (!! not-null assertion, Runtime
// exec) added on top of the todo/complexity starter set.
func TestScanKotlinRules(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/ktbugfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Language != "kotlin" {
		t.Errorf("language = %q, want kotlin", rep.Language)
	}
	for _, id := range []string{"kt:not-null-assertion", "kt:runtime-exec"} {
		if countRule(rep, id) != 1 {
			t.Errorf("expected rule %s to fire exactly once, got %d", id, countRule(rep, id))
		}
	}
}

// TestScanRustRules covers the Rust rules (unsafe block, panic macro) added on
// top of todo/unwrap/complexity.
func TestScanRustRules(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/rustbugfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Language != "rust" {
		t.Errorf("language = %q, want rust", rep.Language)
	}
	for _, id := range []string{"rust:unsafe-block", "rust:panic-macro", "rust:unwrap"} {
		if countRule(rep, id) != 1 {
			t.Errorf("expected rule %s to fire exactly once, got %d", id, countRule(rep, id))
		}
	}
}

// TestScanSwiftRules covers the Swift rules (force-unwrap, force-try) added on
// top of the todo/complexity starter set.
func TestScanSwiftRules(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/swiftbugfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Language != "swift" {
		t.Errorf("language = %q, want swift", rep.Language)
	}
	for _, id := range []string{"swift:force-unwrap", "swift:force-try"} {
		if countRule(rep, id) != 1 {
			t.Errorf("expected rule %s to fire exactly once, got %d", id, countRule(rep, id))
		}
	}
}

// TestScanScalaRules covers the Scala rules (null usage, asInstanceOf) added on
// top of the todo/complexity starter set.
func TestScanScalaRules(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/scalabugfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Language != "scala" {
		t.Errorf("language = %q, want scala", rep.Language)
	}
	for _, id := range []string{"scala:null-usage", "scala:asinstanceof"} {
		if countRule(rep, id) != 1 {
			t.Errorf("expected rule %s to fire exactly once, got %d", id, countRule(rep, id))
		}
	}
}

// TestScanCognitiveComplexity checks the cognitive-complexity rule fires on
// deeply nested (but low-cyclomatic) code, where the cyclomatic high-complexity
// rule does not.
func TestScanCognitiveComplexity(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/cognitivefixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if countRule(rep, "go:cognitive-complexity") != 1 {
		t.Errorf("expected go:cognitive-complexity to fire once, got %d", countRule(rep, "go:cognitive-complexity"))
	}
	// cyclomatic is low here, so the high-complexity rule must NOT fire.
	if countRule(rep, "go:high-complexity") != 0 {
		t.Errorf("go:high-complexity should not fire on low-cyclomatic code, got %d", countRule(rep, "go:high-complexity"))
	}
}

// TestScanInlineSuppression checks that codepulse:ignore (bare and id-scoped)
// and NOSONAR suppress findings on their line, while un-annotated and
// wrong-id lines are still reported.
func TestScanInlineSuppression(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/suppressfixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	// 5 panics total: 3 suppressed (specific id, bare, NOSONAR), 2 reported
	// (un-annotated + wrong-id).
	if n := countRule(rep, "go:panic-usage"); n != 2 {
		t.Errorf("go:panic-usage findings = %d, want 2", n)
	}
	if rep.Summary.SuppressedFindings != 3 {
		t.Errorf("suppressed = %d, want 3", rep.Summary.SuppressedFindings)
	}
	// Reported findings must be the un-annotated and wrong-id lines (13 and 15).
	lines := map[int]bool{}
	for _, f := range rep.Findings {
		if f.RuleID == "go:panic-usage" {
			lines[f.Location.StartLine] = true
		}
	}
	if !lines[13] || !lines[15] {
		t.Errorf("expected panic findings on lines 13 and 15, got %v", lines)
	}
}

// TestScanWithProfile checks that a quality profile disables rules and
// overrides severities through the full scan pipeline.
func TestScanWithProfile(t *testing.T) {
	prof := &rules.Profile{
		Disable:  []string{"go:todo-comment"},
		Severity: map[string]string{"go:panic-usage": "BLOCKER"},
	}
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/gofixture", Profile: prof})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range rep.Findings {
		if f.RuleID == "go:todo-comment" {
			t.Error("go:todo-comment should be disabled by the profile")
		}
		if f.RuleID == "go:panic-usage" && f.Severity != domain.SevBlocker {
			t.Errorf("go:panic-usage severity = %q, want BLOCKER", f.Severity)
		}
	}
	if rep.Summary.BySeverity[domain.SevBlocker] != 1 {
		t.Errorf("BLOCKER count = %d, want 1 (panic-usage promoted)", rep.Summary.BySeverity[domain.SevBlocker])
	}
}

// TestScanProfileCognitiveThreshold lowers the cognitive threshold so the
// fixture's complex function is flagged by the cognitive-complexity rule.
func TestScanProfileCognitiveThreshold(t *testing.T) {
	base, err := scan.Scan(scan.Options{Root: "../../testdata/gofixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if countRule(base, "go:cognitive-complexity") != 0 {
		t.Fatalf("baseline cognitive-complexity = %d, want 0 (default threshold)", countRule(base, "go:cognitive-complexity"))
	}
	lowered, err := scan.Scan(scan.Options{
		Root:    "../../testdata/gofixture",
		Profile: &rules.Profile{CognitiveThreshold: 10},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if n := countRule(lowered, "go:cognitive-complexity"); n != 1 {
		t.Errorf("cognitive-complexity = %d with threshold 10, want 1", n)
	}
}

// TestScanProfileComplexityThreshold raises the complexity threshold so the
// fixture's complex function is no longer flagged.
func TestScanProfileComplexityThreshold(t *testing.T) {
	base, err := scan.Scan(scan.Options{Root: "../../testdata/gofixture"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if countRule(base, "go:high-complexity") != 1 {
		t.Fatalf("baseline high-complexity = %d, want 1", countRule(base, "go:high-complexity"))
	}
	raised, err := scan.Scan(scan.Options{
		Root:    "../../testdata/gofixture",
		Profile: &rules.Profile{ComplexityThreshold: 50},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if n := countRule(raised, "go:high-complexity"); n != 0 {
		t.Errorf("high-complexity = %d with threshold 50, want 0", n)
	}
}

func countRule(rep domain.Report, id string) int {
	n := 0
	for _, f := range rep.Findings {
		if f.RuleID == id {
			n++
		}
	}
	return n
}

func TestScanDuplication(t *testing.T) {
	rep, err := scan.Scan(scan.Options{Root: "../../testdata/dupfixture", MinDupTokens: 20})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.Summary.FilesAnalyzed != 2 {
		t.Fatalf("files analyzed = %d, want 2", rep.Summary.FilesAnalyzed)
	}
	if rep.Summary.DuplicatedLines == 0 {
		t.Error("expected duplicated lines across the two identical files")
	}
	if rep.Summary.DuplicatedLinesDensity <= 0 {
		t.Error("expected positive duplication density")
	}
	for _, m := range rep.Metrics {
		if m.DuplicatedLines == 0 {
			t.Errorf("file %s should report duplicated lines", m.Path)
		}
	}
}
