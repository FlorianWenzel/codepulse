// Package git provides the minimal Git introspection the scanner needs for
// "new code" attribution: detecting a repo and blaming lines to a commit
// author and date.
package git

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// LineInfo is the blame result for one line.
type LineInfo struct {
	Author    string
	Time      time.Time
	Committed bool // false for not-yet-committed (working tree) lines
}

// IsRepo reports whether root is inside a Git work tree.
func IsRepo(root string) bool {
	cmd := exec.Command("git", "-C", root, "rev-parse", "--is-inside-work-tree")
	out, err := cmd.Output()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// zeroSHA marks a not-yet-committed line in porcelain blame output.
const zeroSHA = "0000000000000000000000000000000000000000"

// BlameFile returns blame info per final line number (1-based) for absFile.
// On any error (e.g. the file isn't tracked) it returns a nil map and the
// error; callers should treat missing entries as "new/uncommitted".
func BlameFile(root, absFile string) (map[int]LineInfo, error) {
	cmd := exec.Command("git", "-C", root, "blame", "--porcelain", "--", absFile)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return parsePorcelain(out.Bytes()), nil
}

func parsePorcelain(data []byte) map[int]LineInfo {
	result := map[int]LineInfo{}
	authors := map[string]string{}
	times := map[string]int64{}

	var curSHA string
	var curFinal int
	for _, raw := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(raw, "\t") {
			// Source-content line: attribute the current final line.
			info := LineInfo{Author: authors[curSHA], Committed: curSHA != zeroSHA && curSHA != ""}
			if ts, ok := times[curSHA]; ok {
				info.Time = time.Unix(ts, 0)
			}
			result[curFinal] = info
			continue
		}
		fields := strings.Fields(raw)
		if len(fields) >= 3 {
			sha := strings.TrimPrefix(fields[0], "^")
			if isHex40(sha) {
				curSHA = sha
				if n, err := strconv.Atoi(fields[2]); err == nil {
					curFinal = n
				}
				continue
			}
		}
		switch {
		case strings.HasPrefix(raw, "author "):
			authors[curSHA] = strings.TrimPrefix(raw, "author ")
		case strings.HasPrefix(raw, "author-time "):
			if ts, err := strconv.ParseInt(strings.TrimPrefix(raw, "author-time "), 10, 64); err == nil {
				times[curSHA] = ts
			}
		}
	}
	return result
}

func isHex40(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// Rel makes absFile relative to root (best-effort), for stable reporting.
func Rel(root, absFile string) string {
	if r, err := filepath.Rel(root, absFile); err == nil {
		return r
	}
	return absFile
}
