// Command codepulse-scan analyzes a Go codebase for issues and metrics and
// emits a report (internal JSON or SARIF 2.1.0).
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/FlorianWenzel/codepulse/internal/domain"
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
		format  = flag.String("format", "json", "output format: json | sarif")
		out     = flag.String("o", "", "write report to this file (default: stdout)")
		exclude = flag.String("exclude", "", "comma-separated path substrings to skip")
		failOn  = flag.String("fail-on", "", "exit non-zero if any finding is at least this severity (BLOCKER|CRITICAL|MAJOR|MINOR|INFO)")
		quiet   = flag.Bool("quiet", false, "suppress the human-readable summary on stderr")
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

	rep, err := scan.Scan(scan.Options{Root: root, Excludes: excludes})
	if err != nil {
		return err
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

// ruleMeta exposes the built-in rule set's metadata for SARIF.
func ruleMeta() []report.RuleMeta {
	var m []report.RuleMeta
	for _, r := range rules.GoRules() {
		m = append(m, report.RuleMeta{ID: r.ID, Name: r.Name, Type: r.Type, Severity: r.Severity})
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
}
