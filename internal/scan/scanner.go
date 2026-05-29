// Package scan orchestrates a scan: walk the tree, parse supported files,
// run rules and metrics, and aggregate a report.
package scan

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/FlorianWenzel/codepulse/internal/domain"
	"github.com/FlorianWenzel/codepulse/internal/dup"
	"github.com/FlorianWenzel/codepulse/internal/lang"
	"github.com/FlorianWenzel/codepulse/internal/langspec"
	"github.com/FlorianWenzel/codepulse/internal/metrics"
	"github.com/FlorianWenzel/codepulse/internal/parse"
	"github.com/FlorianWenzel/codepulse/internal/ratings"
	"github.com/FlorianWenzel/codepulse/internal/rules"
	"github.com/FlorianWenzel/codepulse/internal/scm/git"
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
	Root         string   // directory or file to scan
	Excludes     []string // path substrings to skip
	MaxFileSize  int64    // skip files larger than this (bytes); 0 = no limit
	MinDupTokens int      // duplication window size (0 = dup.DefaultMinTokens)
	NewCodeDays  int      // findings introduced within this many days are "new" (0 = disabled)
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
			BySeverity:    map[domain.Severity]int{},
			ByType:        map[domain.IssueType]int{},
			NewBySeverity: map[domain.Severity]int{},
			NewByType:     map[domain.IssueType]int{},
		},
	}

	files, err := collectFiles(opts)
	if err != nil {
		return domain.Report{}, err
	}

	// New-code attribution via git blame (opt-in and only inside a repo).
	newCode := opts.NewCodeDays > 0 && git.IsRepo(opts.Root)
	absRoot, _ := filepath.Abs(opts.Root)
	cutoff := time.Now().AddDate(0, 0, -opts.NewCodeDays)

	contexts := map[lang.Language]*langContext{}
	langsSeen := map[lang.Language]bool{}
	var dupFiles []dup.File

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
		dupFiles = append(dupFiles, dup.File{Path: rel, Tokens: dup.Tokenize(root, src, ctx.spec.IsComment)})

		// Blame the file once for new-code attribution.
		var blame map[int]git.LineInfo
		if newCode {
			if abs, err := filepath.Abs(path); err == nil {
				blame, _ = git.BlameFile(absRoot, abs)
			}
		}

		for _, f := range ctx.engine.Run(rel, root, src) {
			if newCode {
				attributeNewCode(&f, blame, cutoff)
			}
			rep.Findings = append(rep.Findings, f)
			rep.Summary.BySeverity[f.Severity]++
			rep.Summary.ByType[f.Type]++
			rep.Summary.TotalFindings++
			if f.IsNew {
				rep.Summary.NewBySeverity[f.Severity]++
				rep.Summary.NewByType[f.Type]++
				rep.Summary.NewFindings++
			}
		}
	}

	applyDuplication(&rep, dupFiles, opts.MinDupTokens)
	ratings.Compute(&rep)

	rep.Language = joinLangs(langsSeen)
	sortReport(&rep)
	return rep, nil
}

// attributeNewCode tags a finding with its introducing author/date (from git
// blame at its start line) and whether it falls within the new-code window.
// Uncommitted or untracked lines are treated as new.
func attributeNewCode(f *domain.Finding, blame map[int]git.LineInfo, cutoff time.Time) {
	info, ok := blame[f.Location.StartLine]
	if !ok || !info.Committed {
		f.IsNew = true
		return
	}
	f.Author = info.Author
	f.IntroducedAt = info.Time.UTC().Format(time.RFC3339)
	if info.Time.After(cutoff) {
		f.IsNew = true
	}
}

// applyDuplication runs clone detection and folds the results into per-file
// metrics and the project summary (duplicated lines + density vs ncloc).
func applyDuplication(rep *domain.Report, dupFiles []dup.File, minTokens int) {
	res := dup.Detect(dupFiles, minTokens)
	for i := range rep.Metrics {
		if fr, ok := res.ByFile[rep.Metrics[i].Path]; ok {
			rep.Metrics[i].DuplicatedLines = fr.DuplicatedLines
		}
	}
	rep.Summary.DuplicatedLines = res.TotalDuplicatedLines
	if rep.Summary.TotalNcloc > 0 {
		rep.Summary.DuplicatedLinesDensity =
			float64(res.TotalDuplicatedLines) / float64(rep.Summary.TotalNcloc) * 100
	}
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
