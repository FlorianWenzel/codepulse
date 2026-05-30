package rules

import "testing"

func TestScanSecrets(t *testing.T) {
	// Assemble the example tokens via concatenation so the literal patterns do
	// not appear contiguously in THIS source file (which the scanner self-scans);
	// the runtime bytes are still the full token, so detection is exercised.
	aws := "AKIA" + "IOSFODNN7EXAMPLE"
	gh := "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz"
	src := []byte("k = \"" + aws + "\"\ntok = \"" + gh + "\"\nplain = \"nothing to see here\"\n")
	got := map[string]bool{}
	for _, f := range ScanSecrets("x.go", src) {
		got[f.RuleID] = true
		if f.Severity != "BLOCKER" {
			t.Errorf("%s severity = %s, want BLOCKER", f.RuleID, f.Severity)
		}
	}
	for _, id := range []string{"secret:aws-access-key-id", "secret:github-token"} {
		if !got[id] {
			t.Errorf("expected %s to be detected", id)
		}
	}
	if clean := ScanSecrets("x.go", []byte("x = \"just a normal value, length is fine\"\n")); len(clean) != 0 {
		t.Errorf("clean source produced %d secret findings, want 0", len(clean))
	}
}
