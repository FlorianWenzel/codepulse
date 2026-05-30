package rules

import (
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/FlorianWenzel/codepulse/internal/lang"
	"github.com/FlorianWenzel/codepulse/internal/langspec"
	"github.com/FlorianWenzel/codepulse/internal/metrics"
)

// HighComplexityThreshold is the cyclomatic complexity above which a function
// is flagged by the <lang>:high-complexity rule.
const HighComplexityThreshold = 15

// Languages lists every language with a built-in rule set.
func Languages() []lang.Language {
	return []lang.Language{
		lang.Go, lang.Python, lang.JavaScript, lang.TypeScript, lang.Java,
		lang.Ruby, lang.Rust, lang.C, lang.Bash, lang.Cpp, lang.CSharp,
		lang.PHP, lang.Kotlin, lang.Scala, lang.Swift,
	}
}

// ForLanguage returns the built-in rule set for a language (empty if the
// language is unsupported).
func ForLanguage(l lang.Language) []Rule {
	switch l {
	case lang.Go:
		return goRules()
	case lang.Python:
		return pythonRules()
	case lang.JavaScript:
		return jsLikeRules(langspec.JavaScript())
	case lang.TypeScript:
		return jsLikeRules(langspec.TypeScript())
	case lang.Java:
		return javaRules()
	case lang.Ruby:
		return rubyRules()
	case lang.Rust:
		return rustRules()
	case lang.C:
		return cRules()
	case lang.Bash:
		return bashRules()
	case lang.Cpp:
		return cppRules()
	case lang.CSharp:
		return csRules()
	case lang.PHP:
		return phpRules()
	case lang.Kotlin:
		return ktRules()
	case lang.Scala:
		return scalaRules()
	case lang.Swift:
		return swiftRules()
	default:
		return nil
	}
}

// complexityRule builds the high-complexity rule with the default threshold.
func complexityRule(spec langspec.Spec) Rule {
	return complexityRuleWith(spec, HighComplexityThreshold)
}

// complexityRuleWith builds the language-agnostic high-complexity visitor rule
// with an explicit threshold. It reports any named function whose cyclomatic
// complexity exceeds the threshold, located at the function's name.
func complexityRuleWith(spec langspec.Spec, threshold int) Rule {
	id := spec.Prefix + ":high-complexity"
	return Rule{
		ID:        id,
		Name:      "Function is too complex",
		Type:      "CODE_SMELL",
		Severity:  "MAJOR",
		EffortMin: 30,
		Visit: func(root *sitter.Node, src []byte, emit func(*sitter.Node, string)) {
			for _, f := range metrics.Functions(spec, root, src) {
				if f.Complexity <= threshold {
					continue
				}
				target := f.Node
				if name := f.Node.ChildByFieldName(spec.NameField); name != nil {
					target = name
				}
				emit(target, fmt.Sprintf(
					"Function %q has a cyclomatic complexity of %d (threshold %d); refactor it.",
					f.Name, f.Complexity, threshold))
			}
		},
	}
}
