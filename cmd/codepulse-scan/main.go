// Command codepulse-scan analyzes a Go codebase for issues and metrics and
// emits a report (internal JSON or SARIF 2.1.0).
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/importers/coverage"
	"github.com/FlorianWenzel/codepulse/internal/importers/sarif"
	"github.com/FlorianWenzel/codepulse/internal/lang"
	"github.com/FlorianWenzel/codepulse/internal/report"
	"github.com/FlorianWenzel/codepulse/internal/rules"
	"github.com/FlorianWenzel/codepulse/internal/scan"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "codepulse-scan: "+err.Error())
		os.Exit(2)
	}
}

func run() error {
	var (
		format   = flag.String("format", "json", "output format: json | sarif")
		out      = flag.String("o", "", "write report to this file (default: stdout)")
		exclude  = flag.String("exclude", "", "comma-separated path substrings to skip")
		failOn   = flag.String("fail-on", "", "exit non-zero if any finding is at least this severity (BLOCKER|CRITICAL|MAJOR|MINOR|INFO)")
		covPath  = flag.String("coverage", "", "import a coverage report (LCOV, Go coverprofile, or Cobertura XML)")
		dupTok   = flag.Int("dup-tokens", 0, "duplication window size in tokens (0 = default 100)")
		newDays  = flag.Int("new-code-days", 0, "mark findings introduced within N days as new code (requires a git repo)")
		impSarif = flag.String("import-sarif", "", "comma-separated SARIF files from other analyzers to merge")
		quiet    = flag.Bool("quiet", false, "suppress the human-readable summary on stderr")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: codepulse-scan [flags] [path]\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	root := "."
	if flag.NArg() > 0 {
		root = flag.Arg(0)
	}

	var excludes []string
	if *exclude != "" {
		excludes = strings.Split(*exclude, ",")
	}

	rep, err := scan.Scan(scan.Options{Root: root, Excludes: excludes, MinDupTokens: *dupTok, NewCodeDays: *newDays})
	if err != nil {
		return err
	}

	if *impSarif != "" {
		for _, path := range strings.Split(*impSarif, ",") {
			data, err := os.ReadFile(strings.TrimSpace(path))
			if err != nil {
				return err
			}
			findings, err := sarif.Parse(data)
			if err != nil {
				return err
			}
			sarif.Merge(&rep, findings)
		}
	}

	if *covPath != "" {
		data, err := os.ReadFile(*covPath)
		if err != nil {
			return err
		}
		cov, err := coverage.Parse(data)
		if err != nil {
			return err
		}
		coverage.Apply(&rep, cov)
	}

	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	switch *format {
	case "json":
		if err := report.WriteJSON(w, rep); err != nil {
			return err
		}
	case "sarif":
		if err := report.WriteSARIF(w, rep, ruleMeta()); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q (want json or sarif)", *format)
	}

	if !*quiet {
		printSummary(rep)
	}

	if *failOn != "" {
		min := domain.Severity(strings.ToUpper(*failOn))
		for _, f := range rep.Findings {
			if f.Severity.AtLeast(min) {
				os.Exit(1)
			}
		}
	}
	return nil
}

// ruleMeta exposes every built-in rule's metadata for SARIF.
func ruleMeta() []report.RuleMeta {
	var m []report.RuleMeta
	for _, l := range []lang.Language{lang.Go, lang.Python, lang.JavaScript, lang.TypeScript, lang.Java, lang.Ruby, lang.Rust} {
		for _, r := range rules.ForLanguage(l) {
			m = append(m, report.RuleMeta{ID: r.ID, Name: r.Name, Type: r.Type, Severity: r.Severity})
		}
	}
	return m
}

func printSummary(r domain.Report) {
	fmt.Fprintf(os.Stderr, "\nCodePulse scan: %d file(s), %d ncloc, %d finding(s)\n",
		r.Summary.FilesAnalyzed, r.Summary.TotalNcloc, r.Summary.TotalFindings)
	for _, s := range []domain.Severity{domain.SevBlocker, domain.SevCritical, domain.SevMajor, domain.SevMinor, domain.SevInfo} {
		if n := r.Summary.BySeverity[s]; n > 0 {
			fmt.Fprintf(os.Stderr, "  %-9s %d\n", s, n)
		}
	}
	if r.Summary.NewFindings > 0 {
		fmt.Fprintf(os.Stderr, "  new code   %d new finding(s)\n", r.Summary.NewFindings)
	}
	fmt.Fprintf(os.Stderr, "  duplication %.1f%% (%d lines)\n",
		r.Summary.DuplicatedLinesDensity, r.Summary.DuplicatedLines)
	if r.Summary.LinesToCover > 0 {
		fmt.Fprintf(os.Stderr, "  coverage    %.1f%% (%d/%d lines)\n",
			r.Summary.Coverage, r.Summary.CoveredLines, r.Summary.LinesToCover)
	}
}
