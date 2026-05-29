package dup_test

import (
	"testing"

	"github.com/FlorianWenzel/codepulse/internal/dup"
)

func toks(words ...string) []dup.Token {
	out := make([]dup.Token, len(words))
	for i, w := range words {
		out[i] = dup.Token{Text: w, Line: i + 1}
	}
	return out
}

func TestDetectFindsDuplicateWindow(t *testing.T) {
	a := dup.File{Path: "a", Tokens: toks("a", "b", "c", "d", "e")}
	b := dup.File{Path: "b", Tokens: toks("x", "a", "b", "c", "d")}
	// window "a b c d" appears in both files.
	res := dup.Detect([]dup.File{a, b}, 4)
	if res.ByFile["a"].DuplicatedLines == 0 {
		t.Error("file a should report duplicated lines")
	}
	if res.ByFile["b"].DuplicatedLines == 0 {
		t.Error("file b should report duplicated lines")
	}
	if res.TotalDuplicatedLines == 0 {
		t.Error("expected non-zero total duplicated lines")
	}
}

func TestDetectNoFalsePositive(t *testing.T) {
	a := dup.File{Path: "a", Tokens: toks("a", "b", "c", "d", "e")}
	b := dup.File{Path: "b", Tokens: toks("f", "g", "h", "i", "j")}
	res := dup.Detect([]dup.File{a, b}, 3)
	if res.TotalDuplicatedLines != 0 {
		t.Errorf("expected no duplication, got %d lines", res.TotalDuplicatedLines)
	}
}
