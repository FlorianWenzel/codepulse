package scan

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/FlorianWenzel/codepulse/internal/langspec"
	"github.com/FlorianWenzel/codepulse/internal/parse"
)

// lineSuppression records which rules are suppressed on a single source line.
type lineSuppression struct {
	all bool            // suppress every rule on this line
	ids map[string]bool // suppress only these specific rule ids
}

// suppressMarker is CodePulse's native inline-suppression directive.
const suppressMarker = "codepulse:ignore"

// collectSuppressions scans a file's comment nodes for inline-suppression
// directives and maps each to the (1-based) line it applies to. A finding is
// suppressed when a directive sits on its start line. Recognized markers,
// anywhere within a comment:
//
//	codepulse:ignore                 -> suppress all findings on that line
//	codepulse:ignore id1 id2 ...     -> suppress only those rule ids
//	NOSONAR                          -> suppress all findings on that line (Sonar compat)
func collectSuppressions(spec langspec.Spec, root *sitter.Node, src []byte) map[int]lineSuppression {
	out := map[int]lineSuppression{}
	parse.Walk(root, func(n *sitter.Node) {
		if !spec.IsComment(n.Type()) {
			return
		}
		text := n.Content(src)
		line := int(n.StartPoint().Row) + 1

		applyDirective(out, line, text)
	})
	return out
}

// collectSuppressionsText scans raw source lines for suppression directives,
// without needing a parsed tree. Used for non-source files (config, Dockerfile,
// workflow) where the directive can appear in any comment style.
func collectSuppressionsText(src []byte) map[int]lineSuppression {
	out := map[int]lineSuppression{}
	for i, line := range strings.Split(string(src), "\n") {
		applyDirective(out, i+1, line)
	}
	return out
}

// applyDirective parses a codepulse:ignore / NOSONAR marker out of text and
// records it for the given 1-based line.
func applyDirective(out map[int]lineSuppression, line int, text string) {
	if idx := strings.Index(text, suppressMarker); idx >= 0 {
		rest := text[idx+len(suppressMarker):]
		// Drop trailing comment terminators so they aren't parsed as ids.
		rest = strings.NewReplacer("*/", " ", "-->", " ").Replace(rest)
		ids := strings.Fields(rest)
		s := out[line]
		if len(ids) == 0 {
			s.all = true
		} else {
			if s.ids == nil {
				s.ids = map[string]bool{}
			}
			for _, id := range ids {
				s.ids[id] = true
			}
		}
		out[line] = s
		return
	}
	if strings.Contains(text, "NOSONAR") {
		s := out[line]
		s.all = true
		out[line] = s
	}
}

// suppressed reports whether a finding at line for ruleID is suppressed.
func suppressed(sup map[int]lineSuppression, line int, ruleID string) bool {
	s, ok := sup[line]
	if !ok {
		return false
	}
	return s.all || s.ids[ruleID]
}
