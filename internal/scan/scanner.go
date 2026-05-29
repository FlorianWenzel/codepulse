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
	"github.com/FlorianWenzel/codepulse/internal/langspec"
	"github.com/FlorianWenzel/codepulse/internal/metrics"
	"github.com/FlorianWenzel/codepulse/internal/parse"
	"github.com/FlorianWenzel/codepulse/internal/rules"
)

// Version is the scanner version stamped into reports.
const Version = "0.2.0"

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

// langContext bundles the per-language analysis state, built once and reused.
type langContext struct {
	spec   langspec.Spec
	engine *rules.Engine
}

// Scan walks opts.Root, analyzes every supported file, and returns a report.
func Scan(opts Options) (domain.Report, error) {
	rep := domain.Report{
		Tool:    "codepulse-scan",
		Version: Version,
		Summary: domain.Summary{
			BySeverity: map[domain.Severity]int{},
			ByType:     map[domain.IssueType]int{},
		},
	}

	files, err := collectFiles(opts)
	if err != nil {
		return domain.Report{}, err
	}

	contexts := map[lang.Language]*langContext{}
	langsSeen := map[lang.Language]bool{}

	for _, path := range files {
		l := lang.Detect(path)
		ctx, err := contextFor(l, contexts)
		if err != nil {
			return domain.Report{}, err
		}
		if ctx == nil {
			continue // unsupported language
		}
		langsSeen[l] = true

		src, err := os.ReadFile(path)
		if err != nil {
			return domain.Report{}, err
		}
		tree, err := parse.Parse(ctx.spec.TS, src)
		if err != nil {
			return domain.Report{}, err
		}
		root := tree.RootNode()
		rel := relPath(opts.Root, path)

		fm := metrics.Compute(ctx.spec, rel, root, src)
		rep.Metrics = append(rep.Metrics, fm)
		rep.Summary.TotalNcloc += fm.Ncloc
		rep.Summary.FilesAnalyzed++

		for _, f := range ctx.engine.Run(rel, root, src) {
			rep.Findings = append(rep.Findings, f)
			rep.Summary.BySeverity[f.Severity]++
			rep.Summary.ByType[f.Type]++
			rep.Summary.TotalFindings++
		}
	}

	rep.Language = joinLangs(langsSeen)
	sortReport(&rep)
	return rep, nil
}

// contextFor returns (building if needed) the analysis context for a language,
// or nil if the language is unsupported.
func contextFor(l lang.Language, cache map[lang.Language]*langContext) (*langContext, error) {
	if ctx, ok := cache[l]; ok {
		return ctx, nil
	}
	spec, ok := langspec.For(l)
	if !ok {
		cache[l] = nil
		return nil, nil
	}
	rs := rules.ForLanguage(l)
	if len(rs) == 0 {
		cache[l] = nil
		return nil, nil
	}
	eng, err := rules.NewEngine(spec.TS, rs)
	if err != nil {
		return nil, err
	}
	ctx := &langContext{spec: spec, engine: eng}
	cache[l] = ctx
	return ctx, nil
}

func joinLangs(seen map[lang.Language]bool) string {
	var ls []string
	for l := range seen {
		ls = append(ls, string(l))
	}
	sort.Strings(ls)
	return strings.Join(ls, ",")
}

func sortReport(rep *domain.Report) {
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
