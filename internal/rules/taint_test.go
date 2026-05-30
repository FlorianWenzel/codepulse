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

	// Tainted via fmt.Sprintf propagation into the query.
	sprintf := `package p
import ("database/sql"; "fmt"; "os")
func f(db *sql.DB) { q := fmt.Sprintf("select * from t where n='%s'", os.Getenv("N")); _, _ = db.Query(q) }
`
	if got := runRulesSrc(t, lang.Go, sprintf)["go:tainted-sql"]; got != 1 {
		t.Errorf("sprintf-tainted sql: go:tainted-sql fired %d, want 1", got)
	}

	// fmt.Sprintf with only literal args -> no taint, no finding.
	sprintfClean := `package p
import ("database/sql"; "fmt")
func f(db *sql.DB) { q := fmt.Sprintf("select * from t where n='%s'", "static"); _, _ = db.Query(q) }
`
	if got := runRulesSrc(t, lang.Go, sprintfClean)["go:tainted-sql"]; got != 0 {
		t.Errorf("sprintf-clean sql: go:tainted-sql fired %d, want 0", got)
	}
}

// TestGoTaintSprintfExec covers fmt.Sprintf taint propagation into exec.Command.
func TestGoTaintSprintfExec(t *testing.T) {
	vuln := `package p
import ("fmt"; "os"; "os/exec")
func f() { c := fmt.Sprintf("ls %s", os.Getenv("D")); _ = exec.Command("sh", "-c", c) }
`
	if got := runRulesSrc(t, lang.Go, vuln)["go:tainted-exec"]; got != 1 {
		t.Errorf("sprintf-tainted exec: go:tainted-exec fired %d, want 1", got)
	}
	clean := `package p
import ("fmt"; "os/exec")
func f() { c := fmt.Sprintf("ls %s", "static"); _ = exec.Command("sh", "-c", c) }
`
	if got := runRulesSrc(t, lang.Go, clean)["go:tainted-exec"]; got != 0 {
		t.Errorf("sprintf-clean exec: go:tainted-exec fired %d, want 0", got)
	}
}

// TestPyTaintFormatting covers taint propagation through f-strings and
// str.format() into cursor.execute() (the common modern Python SQLi patterns).
// TestPyTaintExec covers dataflow command injection: untrusted input reaching
// os.system / subprocess.* (py:tainted-exec).
func TestPyTaintExec(t *testing.T) {
	osSystem := `def h(request):
    cmd = request.args.get("cmd")
    os.system(cmd)
`
	if got := runRulesSrc(t, lang.Python, osSystem)["py:tainted-exec"]; got != 1 {
		t.Errorf("os.system taint: py:tainted-exec fired %d, want 1", got)
	}
	subproc := `def h(request):
    subprocess.run(request.args.get("cmd"))
`
	if got := runRulesSrc(t, lang.Python, subproc)["py:tainted-exec"]; got != 1 {
		t.Errorf("subprocess taint: py:tainted-exec fired %d, want 1", got)
	}
	clean := `def h():
    subprocess.run(["ls", "-la"])
    os.system("uptime")
`
	if got := runRulesSrc(t, lang.Python, clean)["py:tainted-exec"]; got != 0 {
		t.Errorf("clean exec: py:tainted-exec fired %d, want 0", got)
	}
}

func TestPyTaintFormatting(t *testing.T) {
	fstring := `def h(request):
    x = request.args.get("id")
    q = f"select * from t where id = {x}"
    cursor.execute(q)
`
	if got := runRulesSrc(t, lang.Python, fstring)["py:tainted-sql"]; got != 1 {
		t.Errorf("f-string taint: py:tainted-sql fired %d, want 1", got)
	}

	format := `def h(request):
    x = request.args.get("id")
    q = "select * from t where id = {}".format(x)
    cursor.execute(q)
`
	if got := runRulesSrc(t, lang.Python, format)["py:tainted-sql"]; got != 1 {
		t.Errorf(".format taint: py:tainted-sql fired %d, want 1", got)
	}

	// Literal-only f-string / format -> no taint, no finding.
	clean := `def h():
    name = "static"
    cursor.execute(f"select * from t where n = {name}")
    cursor.execute("select * from t where n = {}".format(name))
`
	if got := runRulesSrc(t, lang.Python, clean)["py:tainted-sql"]; got != 0 {
		t.Errorf("clean formatting: py:tainted-sql fired %d, want 0", got)
	}
}

func TestPyTaintSQL(t *testing.T) {
	vuln := `def handler(request):
    q = "select * from t where id = " + request.args.get("id")
    cursor.execute(q)
`
	if got := runRulesSrc(t, lang.Python, vuln)["py:tainted-sql"]; got != 1 {
		t.Errorf("tainted py sql: fired %d, want 1", got)
	}
	safe := `def handler(request):
    cursor.execute("select * from t where id = %s", (request.args.get("id"),))
`
	if got := runRulesSrc(t, lang.Python, safe)["py:tainted-sql"]; got != 0 {
		t.Errorf("parameterized py sql: fired %d, want 0", got)
	}
}

func TestJSTaintEval(t *testing.T) {
	vuln := "function h(req) { const id = req.query.id; eval(id); }\n"
	if got := runRulesSrc(t, lang.JavaScript, vuln)["js:tainted-eval"]; got != 1 {
		t.Errorf("tainted js eval (propagated): fired %d, want 1", got)
	}
	direct := "function h(req) { eval(req.body.code); }\n"
	if got := runRulesSrc(t, lang.JavaScript, direct)["js:tainted-eval"]; got != 1 {
		t.Errorf("tainted js eval (direct): fired %d, want 1", got)
	}
	clean := "function h(req) { eval('1 + 1'); }\n"
	if got := runRulesSrc(t, lang.JavaScript, clean)["js:tainted-eval"]; got != 0 {
		t.Errorf("clean js eval: fired %d, want 0", got)
	}
	ts := "function h(req: any) { const x = req.params.q; eval(x); }\n"
	if got := runRulesSrc(t, lang.TypeScript, ts)["ts:tainted-eval"]; got != 1 {
		t.Errorf("tainted ts eval: fired %d, want 1", got)
	}
}

func TestJSTaintXSSExec(t *testing.T) {
	xss := "function h(req, el) { el.innerHTML = req.body.html; }\n"
	if got := runRulesSrc(t, lang.JavaScript, xss)["js:tainted-xss"]; got != 1 {
		t.Errorf("tainted xss: fired %d, want 1", got)
	}
	exec := "function h(req, cp) { const c = req.query.cmd; cp.exec(c); }\n"
	if got := runRulesSrc(t, lang.JavaScript, exec)["js:tainted-exec"]; got != 1 {
		t.Errorf("tainted exec: fired %d, want 1", got)
	}
	clean := "function h(el) { el.innerHTML = 'static'; }\n"
	if got := runRulesSrc(t, lang.JavaScript, clean)["js:tainted-xss"]; got != 0 {
		t.Errorf("clean xss: fired %d, want 0", got)
	}
}
