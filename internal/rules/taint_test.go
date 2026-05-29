package rules_test

import "testing"

import "github.com/FlorianWenzel/codepulse/internal/lang"

func TestGoTaintExec(t *testing.T) {
	// Tainted: os.Getenv -> exec.Command (direct).
	direct := `package p
import ("os"; "os/exec")
func f() { name := os.Getenv("CMD"); _ = exec.Command(name) }
`
	if got := runRulesSrc(t, lang.Go, direct)["go:tainted-exec"]; got != 1 {
		t.Errorf("direct taint: go:tainted-exec fired %d, want 1", got)
	}

	// Tainted via one-hop propagation: n := os.Getenv; m := n; exec.Command(m).
	propagated := `package p
import ("os"; "os/exec")
func f() { n := os.Getenv("CMD"); m := n; _ = exec.Command(m) }
`
	if got := runRulesSrc(t, lang.Go, propagated)["go:tainted-exec"]; got != 1 {
		t.Errorf("propagated taint: go:tainted-exec fired %d, want 1", got)
	}

	// Not tainted: literal argument -> no finding (no false positive).
	clean := `package p
import "os/exec"
func f() { _ = exec.Command("ls", "-la") }
`
	if got := runRulesSrc(t, lang.Go, clean)["go:tainted-exec"]; got != 0 {
		t.Errorf("clean: go:tainted-exec fired %d, want 0", got)
	}

	// Not tainted: arg is a non-tainted local.
	untainted := `package p
import "os/exec"
func f(name string) { safe := "ls"; _ = exec.Command(safe, name) }
`
	if got := runRulesSrc(t, lang.Go, untainted)["go:tainted-exec"]; got != 0 {
		t.Errorf("untainted local: go:tainted-exec fired %d, want 0", got)
	}

	// os.Args source -> exec sink.
	osArgs := `package p
import ("os"; "os/exec")
func f() { _ = exec.Command(os.Args[1]) }
`
	if got := runRulesSrc(t, lang.Go, osArgs)["go:tainted-exec"]; got != 1 {
		t.Errorf("os.Args source: go:tainted-exec fired %d, want 1", got)
	}
}

func TestGoTaintSQL(t *testing.T) {
	// Tainted concatenation into a SQL query.
	vuln := `package p
import ("database/sql"; "os")
func f(db *sql.DB) { _, _ = db.Query("select * from t where id = " + os.Getenv("ID")) }
`
	if got := runRulesSrc(t, lang.Go, vuln)["go:tainted-sql"]; got != 1 {
		t.Errorf("tainted sql: go:tainted-sql fired %d, want 1", got)
	}

	// Parameterized / literal query -> no finding.
	safe := `package p
import "database/sql"
func f(db *sql.DB, id string) { _, _ = db.Query("select * from t where id = $1", id) }
`
	if got := runRulesSrc(t, lang.Go, safe)["go:tainted-sql"]; got != 0 {
		t.Errorf("parameterized sql: go:tainted-sql fired %d, want 0", got)
	}
}
