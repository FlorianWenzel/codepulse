// Package lang maps files to the language CodePulse should analyze them as.
package lang

import (
	"path/filepath"
	"strings"
)

// Language is a supported analysis language.
type Language string

const (
	Go         Language = "go"
	Python     Language = "python"
	JavaScript Language = "javascript"
	TypeScript Language = "typescript"
	Java       Language = "java"
	Ruby       Language = "ruby"
	Rust       Language = "rust"
	C          Language = "c"
	Bash       Language = "bash"
	Unknown    Language = ""
)

// extMap maps file extensions to languages. Later phases add Java etc. here
// (plus their grammars in langspec and rule sets in rules).
var extMap = map[string]Language{
	".go":   Go,
	".py":   Python,
	".js":   JavaScript,
	".jsx":  JavaScript,
	".mjs":  JavaScript,
	".cjs":  JavaScript,
	".ts":   TypeScript,
	".tsx":  TypeScript,
	".java": Java,
	".rb":   Ruby,
	".rs":   Rust,
	".c":    C,
	".h":    C,
	".sh":   Bash,
	".bash": Bash,
}

// Detect returns the language for a path, or Unknown if unsupported.
func Detect(path string) Language {
	ext := strings.ToLower(filepath.Ext(path))
	return extMap[ext]
}

// IsSupported reports whether the path is a language CodePulse can analyze.
func IsSupported(path string) bool { return Detect(path) != Unknown }
