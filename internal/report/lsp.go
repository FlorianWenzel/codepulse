package report

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/FlorianWenzel/codepulse/internal/domain"
)

// LSP PublishDiagnostics-style output, grouped by file, for IDE integration.
type lspFileDiagnostics struct {
	URI         string          `json:"uri"`
	Diagnostics []lspDiagnostic `json:"diagnostics"`
}

type lspDiagnostic struct {
	Range    lspRange `json:"range"`
	Severity int      `json:"severity"` // 1=Error 2=Warning 3=Information 4=Hint
	Code     string   `json:"code"`
	Source   string   `json:"source"`
	Message  string   `json:"message"`
}

type lspRange struct {
	Start lspPos `json:"start"`
	End   lspPos `json:"end"`
}

type lspPos struct {
	Line      int `json:"line"`      // 0-based
	Character int `json:"character"` // 0-based
}

func lspSeverity(s domain.Severity) int {
	switch s {
	case domain.SevBlocker, domain.SevCritical:
		return 1
	case domain.SevMajor, domain.SevMinor:
		return 2
	default:
		return 3
	}
}

// WriteLSP writes findings as LSP diagnostics grouped by file URI. Lines and
// columns are converted from CodePulse's 1-based to LSP's 0-based.
func WriteLSP(w io.Writer, r domain.Report) error {
	byFile := map[string][]lspDiagnostic{}
	for _, f := range r.Findings {
		byFile[f.Location.File] = append(byFile[f.Location.File], lspDiagnostic{
			Range: lspRange{
				Start: lspPos{Line: max0(f.Location.StartLine - 1), Character: max0(f.Location.StartCol - 1)},
				End:   lspPos{Line: max0(f.Location.EndLine - 1), Character: max0(f.Location.EndCol - 1)},
			},
			Severity: lspSeverity(f.Severity),
			Code:     f.RuleID,
			Source:   "codepulse",
			Message:  f.Message,
		})
	}
	out := make([]lspFileDiagnostics, 0, len(byFile))
	for uri, diags := range byFile {
		out = append(out, lspFileDiagnostics{URI: uri, Diagnostics: diags})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URI < out[j].URI })

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}
