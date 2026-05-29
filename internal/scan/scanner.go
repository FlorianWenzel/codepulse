// Package scan orchestrates a scan: walk the tree, parse supported files,
// run rules and metrics, and aggregate a report.
package scan

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/lang"
	"github.com/FlorianWenzel/codepulse/internal/metrics"
	"github.com/FlorianWenzel/codepulse/internal/parse"
	"github.com/FlorianWenzel/codepulse/internal/rules"
)

// Version is the scanner version stamped into reports.
const Version = "0.1.0"

// skipDirs are directory names never descended into.
var skipDirs = map[string]bool{
	".git": true, "vendor": true, "node_modules": true,
	".idea": true, ".vscode": true, "dist": true, "bin": true,
}

// Options configures a scan.
type Options struct {
	Root        string   // directory or file to scan
	Excludes    []string // path substrings to skip
	MaxFileSize int64    // skip files larger than this (bytes); 0 = no limit
}

// Scan walks opts.Root, analyzes every supported file, and returns a report.
func Scan(opts Options) (domain.Report, error) {
	engine, err := rules.NewEngine(parse.GoLanguage(), rules.GoRules())
	if err != nil {
		return domain.Report{}, err
	}

	rep := domain.Report{
		Tool:     "codepulse-scan",
		Version:  Version,
		Language: "go",
		Summary: domain.Summary{
			BySeverity: map[domain.Severity]int{},
			ByType:     map[domain.IssueType]int{},
		},
	}

	files, err := collectFiles(opts)
	if err != nil {
		return domain.Report{}, err
	}

	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			return domain.Report{}, err
		}
		tree, err := parse.Parse(src)
		if err != nil {
			return domain.Report{}, err
		}
		root := tree.RootNode()

		rel := relPath(opts.Root, path)

		fm := metrics.Compute(rel, root, src)
		rep.Metrics = append(rep.Metrics, fm)
		rep.Summary.TotalNcloc += fm.Ncloc
		rep.Summary.FilesAnalyzed++

		for _, f := range engine.Run(rel, root, src) {
			rep.Findings = append(rep.Findings, f)
			rep.Summary.BySeverity[f.Severity]++
			rep.Summary.ByType[f.Type]++
			rep.Summary.TotalFindings++
		}
	}

	// Deterministic ordering: by file, then line, then rule.
	sort.Slice(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.Location.File != b.Location.File {
			return a.Location.File < b.Location.File
		}
		if a.Location.StartLine != b.Location.StartLine {
			return a.Location.StartLine < b.Location.StartLine
		}
		return a.RuleID < b.RuleID
	})
	sort.Slice(rep.Metrics, func(i, j int) bool { return rep.Metrics[i].Path < rep.Metrics[j].Path })

	return rep, nil
}

// collectFiles returns the sorted list of supported files under opts.Root.
func collectFiles(opts Options) ([]string, error) {
	info, err := os.Stat(opts.Root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if lang.IsSupported(opts.Root) {
			return []string{opts.Root}, nil
		}
		return nil, nil
	}

	var files []string
	err = filepath.WalkDir(opts.Root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != opts.Root && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !lang.IsSupported(path) || excluded(path, opts.Excludes) {
			return nil
		}
		if opts.MaxFileSize > 0 {
			if fi, e := d.Info(); e == nil && fi.Size() > opts.MaxFileSize {
				return nil
			}
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func excluded(path string, excludes []string) bool {
	for _, e := range excludes {
		if e != "" && strings.Contains(path, e) {
			return true
		}
	}
	return false
}

// relPath makes path relative to root (or its parent, when root is a file)
// so reports use stable, project-relative paths.
func relPath(root, path string) string {
	base := root
	if fi, err := os.Stat(root); err == nil && !fi.IsDir() {
		base = filepath.Dir(root)
	}
	if rel, err := filepath.Rel(base, path); err == nil {
		return rel
	}
	return path
}
