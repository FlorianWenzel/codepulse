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
}
