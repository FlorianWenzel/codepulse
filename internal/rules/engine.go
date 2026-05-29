// Package rules defines the rule model and the engine that runs rules against
// a parsed file to produce findings.
package rules

import (
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/FlorianWenzel/codepulse/internal/domain"
)

// Rule is a single check. A rule is either query-based (Query set) or
// visitor-based (Visit set).
//
//   - Query-based: the tree-sitter Query runs over the file; the node captured
//     as Capture is reported. Built-in predicates (#eq?, #match?) are applied.
//     If Predicate is set it gets the final say and supplies the message;
//     otherwise Message is used verbatim.
//   - Visitor-based: Visit walks the tree itself and emits findings. Used for
//     checks the query language can't express (e.g. numeric thresholds).
type Rule struct {
	ID        string
	Name      string
	Type      domain.IssueType
	Severity  domain.Severity
	EffortMin int

	// Query-based fields.
	Query     string
	Capture   string // capture name to report; defaults to "flag"
	Message   string
	Predicate func(n *sitter.Node, src []byte) (msg string, keep bool)

	// Visitor-based field.
	Visit func(root *sitter.Node, src []byte, emit func(n *sitter.Node, msg string))
}

// Engine runs a set of rules against parsed files.
type Engine struct {
	lang     *sitter.Language
	rules    []Rule
	compiled map[string]*sitter.Query // ruleID -> compiled query (cache)
}

// NewEngine compiles the given rules for a language. Compilation errors are
// returned so a bad query fails loudly rather than silently skipping.
func NewEngine(lang *sitter.Language, rs []Rule) (*Engine, error) {
	e := &Engine{lang: lang, rules: rs, compiled: map[string]*sitter.Query{}}
	for _, r := range rs {
		if r.Query == "" {
			continue
		}
		q, err := sitter.NewQuery([]byte(r.Query), lang)
		if err != nil {
			return nil, fmt.Errorf("rule %s: invalid query: %w", r.ID, err)
		}
		e.compiled[r.ID] = q
	}
	return e, nil
}

// Rules returns the rule set, for metadata (e.g. SARIF rule descriptors).
func (e *Engine) Rules() []Rule { return e.rules }

// Run analyzes one file and returns its findings.
func (e *Engine) Run(path string, root *sitter.Node, src []byte) []domain.Finding {
	var out []domain.Finding
	for _, r := range e.rules {
		emit := func(n *sitter.Node, msg string) {
			out = append(out, domain.Finding{
				RuleID:    r.ID,
				Message:   msg,
				Severity:  r.Severity,
				Type:      r.Type,
				Location:  loc(path, n),
				EffortMin: r.EffortMin,
			})
		}

		if r.Visit != nil {
			r.Visit(root, src, emit)
			continue
		}

		q := e.compiled[r.ID]
		if q == nil {
			continue
		}
		capture := r.Capture
		if capture == "" {
			capture = "flag"
		}
		qc := sitter.NewQueryCursor()
		qc.Exec(q, root)
		for {
			m, ok := qc.NextMatch()
			if !ok {
				break
			}
			m = qc.FilterPredicates(m, src)
			for _, c := range m.Captures {
				if q.CaptureNameForId(c.Index) != capture {
					continue
				}
				node := c.Node
				msg := r.Message
				if r.Predicate != nil {
					var keep bool
					msg, keep = r.Predicate(node, src)
					if !keep {
						continue
					}
				}
				emit(node, msg)
			}
		}
	}
	return out
}

// loc converts a tree-sitter node's 0-based points into a 1-based Location.
func loc(path string, n *sitter.Node) domain.Location {
	s, e := n.StartPoint(), n.EndPoint()
	return domain.Location{
		File:      path,
		StartLine: int(s.Row) + 1,
		StartCol:  int(s.Column) + 1,
		EndLine:   int(e.Row) + 1,
		EndCol:    int(e.Column) + 1,
	}
}
