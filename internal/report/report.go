// Package report serializes a scan into output formats: the internal JSON
// report and SARIF 2.1.0.
package report

import (
	"encoding/json"
	"io"

	"github.com/FlorianWenzel/codepulse/internal/domain"
)

// WriteJSON writes the internal CodePulse report as indented JSON.
func WriteJSON(w io.Writer, r domain.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
