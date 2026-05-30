// Command codepulse-scan analyzes a Go codebase for issues and metrics and
// emits a report (internal JSON or SARIF 2.1.0).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/importers/coverage"
	"github.com/FlorianWenzel/codepulse/internal/importers/sarif"
	"github.com/FlorianWenzel/codepulse/internal/importers/semgrep"
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
		format     = flag.String("format", "json", "output format: json | sarif | lsp")
		out        = flag.String("o", "", "write report to this file (default: stdout)")
		exclude    = flag.String("exclude", "", "comma-separated path substrings to skip")
		failOn     = flag.String("fail-on", "", "exit non-zero if any finding is at least this severity (BLOCKER|CRITICAL|MAJOR|MINOR|INFO)")
		covPath    = flag.String("coverage", "", "import a coverage report (LCOV, Go coverprofile, or Cobertura XML)")
		dupTok     = flag.Int("dup-tokens", 0, "duplication window size in tokens (0 = default 100)")
		newDays    = flag.Int("new-code-days", 0, "mark findings introduced within N days as new code (requires a git repo)")
		impSarif   = flag.String("import-sarif", "", "comma-separated SARIF files from other analyzers to merge")
		semgrepCfg = flag.String("semgrep", "", "run semgrep with this --config and merge its findings (requires semgrep on PATH)")
		since      = flag.String("since", "", "incremental: only analyze files changed since this git ref")
		rulesDump  = flag.Bool("rules", false, "print the built-in rule catalogue as JSON and exit")
		showVer    = flag.Bool("version", false, "print the codepulse-scan version and exit")
		profile    = flag.String("profile", "", "quality profile file (YAML/JSON); defaults to .codepulse.yml in the scan root")
		quiet      = flag.Bool("quiet", false, "suppress the human-readable summary on stderr")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: codepulse-scan [flags] [path]\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVer {
		fmt.Println("codepulse-scan " + scan.Version)
		return nil
	}
	if *rulesDump {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rules.Catalog())
	}

	root := "."
	if flag.NArg() > 0 {
		root = flag.Arg(0)
	}

	var excludes []string
	if *exclude != "" {
		excludes = strings.Split(*exclude, ",")
	}

	prof, err := loadProfile(*profile, root)
	if err != nil {
		return err
	}

	rep, err := scan.Scan(scan.Options{Root: root, Excludes: excludes, MinDupTokens: *dupTok, NewCodeDays: *newDays, Since: *since, Profile: prof})
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

	if *semgrepCfg != "" {
		findings, err := semgrep.Run(context.Background(), *semgrepCfg, root)
		if err != nil {
			return err
		}
		sarif.Merge(&rep, findings)
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
	case "lsp":
		if err := report.WriteLSP(w, rep); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q (want json, sarif, or lsp)", *format)
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

// loadProfile resolves a quality profile: the explicit -profile path if given,
// otherwise .codepulse.yml / .codepulse.yaml auto-discovered in the scan root
// (a directory). Returns nil (no-op profile) when none is configured.
func loadProfile(explicit, root string) (*rules.Profile, error) {
	if explicit != "" {
		return rules.LoadProfile(explicit)
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, nil
	}
	for _, name := range []string{".codepulse.yml", ".codepulse.yaml"} {
		path := filepath.Join(root, name)
		if _, err := os.Stat(path); err == nil {
			return rules.LoadProfile(path)
		}
	}
	return nil, nil
}

// ruleMeta exposes every built-in rule's metadata (incl. description + CWE/tags)
// for SARIF, sourced from the rule catalogue.
func ruleMeta() []report.RuleMeta {
	var m []report.RuleMeta
	for _, c := range rules.Catalog() {
		m = append(m, report.RuleMeta{
			ID: c.ID, Name: c.Name, Type: c.Type, Severity: c.Severity,
			Description: c.Description, Remediation: c.Remediation, CWE: c.CWE, Tags: c.Tags,
		})
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
	if r.Summary.SuppressedFindings > 0 {
		fmt.Fprintf(os.Stderr, "  suppressed %d finding(s) via inline codepulse:ignore / NOSONAR\n", r.Summary.SuppressedFindings)
	}
	fmt.Fprintf(os.Stderr, "  duplication %.1f%% (%d lines)\n",
		r.Summary.DuplicatedLinesDensity, r.Summary.DuplicatedLines)
	if r.Summary.LinesToCover > 0 {
		fmt.Fprintf(os.Stderr, "  coverage    %.1f%% (%d/%d lines)\n",
			r.Summary.Coverage, r.Summary.CoveredLines, r.Summary.LinesToCover)
	}
}
