// Package dup detects duplicated code across files using a token-window index.
//
// Each file is reduced to a stream of significant tokens (comments and
// whitespace dropped). Identical windows of minTokens consecutive tokens that
// appear in two or more places mark their spanned lines as duplicated. This is
// a straightforward, deterministic clone detector; a rolling-hash/suffix-based
// implementation can replace it later without changing the interface.
package dup

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/FlorianWenzel/codepulse/internal/parse"
)

// DefaultMinTokens mirrors SonarQube's clone size (~100 tokens).
const DefaultMinTokens = 100

// Token is one significant lexical token with the line it starts on (1-based).
type Token struct {
	Text string
	Line int
}

// File is a tokenized file to be checked for duplication.
type File struct {
	Path   string
	Tokens []Token
}

// FileResult is the per-file duplication outcome.
type FileResult struct {
	DuplicatedLines int
}

// Result is the whole-project duplication outcome.
type Result struct {
	ByFile               map[string]FileResult
	TotalDuplicatedLines int
}

// Tokenize extracts significant tokens (leaf nodes that aren't comments or
// whitespace) from a parsed file. isComment reports comment node types.
func Tokenize(root *sitter.Node, src []byte, isComment func(string) bool) []Token {
	var toks []Token
	parse.Walk(root, func(n *sitter.Node) {
		if n.ChildCount() != 0 || isComment(n.Type()) {
			return
		}
		t := n.Content(src)
		if strings.TrimSpace(t) == "" {
			return
		}
		toks = append(toks, Token{Text: t, Line: int(n.StartPoint().Row) + 1})
	})
	return toks
}

type occurrence struct {
	file  int
	start int
}

// Detect finds duplicated token windows across all files and reports the
// number of duplicated lines per file.
func Detect(files []File, minTokens int) Result {
	if minTokens <= 0 {
		minTokens = DefaultMinTokens
	}

	index := map[string][]occurrence{}
	for fi, f := range files {
		for s := 0; s+minTokens <= len(f.Tokens); s++ {
			index[windowKey(f.Tokens[s:s+minTokens])] = append(
				index[windowKey(f.Tokens[s:s+minTokens])], occurrence{fi, s})
		}
	}

	dupLines := make([]map[int]bool, len(files))
	for i := range dupLines {
		dupLines[i] = map[int]bool{}
	}
	for _, occs := range index {
		if len(occs) < 2 {
			continue
		}
		for _, o := range occs {
			toks := files[o.file].Tokens
			for j := o.start; j < o.start+minTokens; j++ {
				dupLines[o.file][toks[j].Line] = true
			}
		}
	}

	res := Result{ByFile: make(map[string]FileResult, len(files))}
	for fi, f := range files {
		n := len(dupLines[fi])
		res.ByFile[f.Path] = FileResult{DuplicatedLines: n}
		res.TotalDuplicatedLines += n
	}
	return res
}

func windowKey(toks []Token) string {
	var b strings.Builder
	for _, t := range toks {
		b.WriteString(t.Text)
		b.WriteByte('\x00') // separator that can't appear in a token
	}
	return b.String()
}
