// Package parse wraps tree-sitter so the rest of the scanner never touches
// the CGo bindings directly.
package parse

import (
	"context"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/golang"
)

// GoLanguage returns the tree-sitter grammar for Go.
func GoLanguage() *sitter.Language { return golang.GetLanguage() }

// Parse parses Go source into a syntax tree. Parse errors do not fail the
// call — tree-sitter returns a partial tree with ERROR nodes, which the
// caller can still analyze.
func Parse(src []byte) (*sitter.Tree, error) {
	p := sitter.NewParser()
	p.SetLanguage(GoLanguage())
	return p.ParseCtx(context.Background(), nil, src)
}

// Walk invokes fn for n and every descendant, depth-first.
func Walk(n *sitter.Node, fn func(*sitter.Node)) {
	fn(n)
	for i := 0; i < int(n.ChildCount()); i++ {
		Walk(n.Child(i), fn)
	}
}
