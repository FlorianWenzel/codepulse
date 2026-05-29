package rules

import (
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/metrics"
)

// HighComplexityThreshold is the cyclomatic complexity above which a function
// is flagged by go:high-complexity.
const HighComplexityThreshold = 15

// GoRules returns CodePulse's built-in Go rule set ("the CodePulse Way"
// starter profile). Each rule is deliberately low-false-positive.
func GoRules() []Rule {
	return []Rule{
		{
			ID:        "go:panic-usage",
			Name:      "panic() should not be used for normal control flow",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMajor,
			EffortMin: 15,
			// Match calls of the bare builtin panic(...).
			Query:   `(call_expression function: (identifier) @fn (#eq? @fn "panic")) @flag`,
			Capture: "flag",
			Message: "Avoid panic(); return an error to the caller instead.",
		},
		{
			ID:        "go:todo-comment",
			Name:      "Track and resolve TODO/FIXME comments",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevInfo,
			EffortMin: 5,
			// Built-in #match? predicate filters to actionable markers.
			Query:   `((comment) @flag (#match? @flag "(TODO|FIXME|XXX)"))`,
			Capture: "flag",
			Message: "Complete the task described by this TODO/FIXME marker.",
		},
		{
			ID:        "go:empty-block",
			Name:      "Empty blocks should be removed or documented",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMinor,
			EffortMin: 5,
			Query:     `(block) @flag`,
			Capture:   "flag",
			// A block with no named children is empty. Predicate supplies the
			// final decision the query language can't express.
			Predicate: func(n *sitter.Node, src []byte) (string, bool) {
				if n.NamedChildCount() > 0 {
					return "", false
				}
				return "Remove this empty block, or add a comment explaining why it is empty.", true
			},
		},
		{
			ID:        "go:high-complexity",
			Name:      "Function is too complex",
			Type:      domain.TypeCodeSmell,
			Severity:  domain.SevMajor,
			EffortMin: 30,
			// Visitor rule: walk functions, flag those over the threshold,
			// report at the function's name.
			Visit: func(root *sitter.Node, src []byte, emit func(*sitter.Node, string)) {
				for _, f := range metrics.Functions(root, src) {
					if f.Complexity <= HighComplexityThreshold {
						continue
					}
					target := f.Node
					if name := f.Node.ChildByFieldName("name"); name != nil {
						target = name
					}
					emit(target, fmt.Sprintf(
						"Function %q has a cyclomatic complexity of %d (threshold %d); refactor it.",
						f.Name, f.Complexity, HighComplexityThreshold))
				}
			},
		},
	}
}
