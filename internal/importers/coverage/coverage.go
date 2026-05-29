// Package coverage imports external test-coverage reports (LCOV, Go
// coverprofile, Cobertura XML) into CodePulse's coverage model and merges them
// onto a scan report.
package coverage

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"

	"github.com/FlorianWenzel/codepulse/internal/domain"
)

// FileCoverage holds line-coverage counts for one file.
type FileCoverage struct {
	LinesToCover int
	CoveredLines int
}

// Coverage maps a file path (as written in the report) to its coverage.
type Coverage map[string]FileCoverage

// Parse autodetects the format of data and parses it.
func Parse(data []byte) (Coverage, error) {
	trimmed := bytes.TrimSpace(data)
	switch {
	case bytes.HasPrefix(trimmed, []byte("mode:")):
		return parseGoCover(data)
	case bytes.Contains(trimmed, []byte("<coverage")):
		return parseCobertura(data)
	case bytes.Contains(trimmed, []byte("SF:")) || bytes.Contains(trimmed, []byte("DA:")):
		return parseLCOV(data)
	default:
		return nil, fmt.Errorf("coverage: unrecognized format")
	}
}

// parseLCOV reads SF:/DA: records.
func parseLCOV(data []byte) (Coverage, error) {
	cov := Coverage{}
	var cur string
	var fc FileCoverage
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "SF:"):
			cur = strings.TrimPrefix(line, "SF:")
			fc = FileCoverage{}
		case strings.HasPrefix(line, "DA:"):
			parts := strings.SplitN(strings.TrimPrefix(line, "DA:"), ",", 2)
			if len(parts) != 2 {
				continue
			}
			hits, _ := strconv.Atoi(parts[1])
			fc.LinesToCover++
			if hits > 0 {
				fc.CoveredLines++
			}
		case line == "end_of_record":
			if cur != "" {
				cov[cur] = fc
			}
			cur = ""
		}
	}
	return cov, sc.Err()
}

// parseGoCover reads `go test -coverprofile` output (statement-based).
func parseGoCover(data []byte) (Coverage, error) {
	cov := Coverage{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "mode:") {
			continue
		}
		// file.go:startLine.col,endLine.col numStmts count
		colon := strings.LastIndex(line, ":")
		if colon < 0 {
			continue
		}
		file := line[:colon]
		fields := strings.Fields(line[colon+1:])
		if len(fields) != 3 {
			continue
		}
		numStmts, _ := strconv.Atoi(fields[1])
		count, _ := strconv.Atoi(fields[2])
		fc := cov[file]
		fc.LinesToCover += numStmts
		if count > 0 {
			fc.CoveredLines += numStmts
		}
		cov[file] = fc
	}
	return cov, sc.Err()
}

// Cobertura XML structures (subset).
type coberturaCoverage struct {
	Packages struct {
		Package []struct {
			Classes struct {
				Class []struct {
					Filename string `xml:"filename,attr"`
					Lines    struct {
						Line []struct {
							Hits int `xml:"hits,attr"`
						} `xml:"line"`
					} `xml:"lines"`
				} `xml:"class"`
			} `xml:"classes"`
		} `xml:"package"`
	} `xml:"packages"`
}

func parseCobertura(data []byte) (Coverage, error) {
	var doc coberturaCoverage
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("coverage: cobertura: %w", err)
	}
	cov := Coverage{}
	for _, pkg := range doc.Packages.Package {
		for _, cls := range pkg.Classes.Class {
			fc := cov[cls.Filename]
			for _, ln := range cls.Lines.Line {
				fc.LinesToCover++
				if ln.Hits > 0 {
					fc.CoveredLines++
				}
			}
			cov[cls.Filename] = fc
		}
	}
	return cov, nil
}

// Apply merges coverage onto a report's per-file metrics (matching by exact
// path or path suffix) and recomputes the project coverage summary.
func Apply(rep *domain.Report, cov Coverage) {
	for i := range rep.Metrics {
		m := &rep.Metrics[i]
		if fc, ok := match(cov, m.Path); ok {
			m.LinesToCover = fc.LinesToCover
			m.CoveredLines = fc.CoveredLines
		}
	}
	total, covered := 0, 0
	for _, m := range rep.Metrics {
		total += m.LinesToCover
		covered += m.CoveredLines
	}
	rep.Summary.LinesToCover = total
	rep.Summary.CoveredLines = covered
	if total > 0 {
		rep.Summary.Coverage = pct(covered, total)
	}
}

// match finds coverage for a report path, allowing the coverage report to use
// longer absolute paths than the project-relative report path.
func match(cov Coverage, path string) (FileCoverage, bool) {
	if fc, ok := cov[path]; ok {
		return fc, true
	}
	for k, fc := range cov {
		if strings.HasSuffix(k, "/"+path) || strings.HasSuffix(path, "/"+k) {
			return fc, true
		}
	}
	return FileCoverage{}, false
}

func pct(part, whole int) float64 {
	if whole == 0 {
		return 0
	}
	return float64(part) / float64(whole) * 100
}
