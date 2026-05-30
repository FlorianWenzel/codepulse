package rules

import (
	"regexp"
	"strings"

	"github.com/FlorianWenzel/codepulse/internal/domain"
)

// Dockerfile checks are line-based (Dockerfiles aren't one of the tree-sitter
// languages). They cover a few high-signal, low-false-positive issues.

var (
	reFromLatest = regexp.MustCompile(`(?i)^\s*FROM\s+\S+:latest(\s|$|\s+AS\s)`)
	reCurlPipeSh = regexp.MustCompile(`(?i)\b(?:curl|wget)\b.*\|\s*(?:sh|bash|zsh)\b`)
	reSudo       = regexp.MustCompile(`(?i)^\s*RUN\s+.*\bsudo\b`)
	reUserInstr  = regexp.MustCompile(`(?i)^\s*USER\s+\S`)
	reRunnable   = regexp.MustCompile(`(?i)^\s*(?:CMD|ENTRYPOINT)\s`)
	reAddInstr   = regexp.MustCompile(`(?i)^\s*ADD\s+(?:--\S+\s+)*[^\s]+\s`)
)

// IsDockerfile reports whether path is a Dockerfile by name.
func IsDockerfile(path string) bool {
	base := strings.ToLower(filepathBase(path))
	return base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile")
}

// filepathBase is a tiny basename helper (avoids importing path/filepath here).
func filepathBase(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// ScanDockerfile runs the Dockerfile checks over src (1-based line locations).
func ScanDockerfile(path string, src []byte) []domain.Finding {
	var out []domain.Finding
	add := func(id, msg string, sev domain.Severity, typ domain.IssueType, line, effort int) {
		out = append(out, domain.Finding{
			RuleID: id, Message: msg, Severity: sev, Type: typ, EffortMin: effort,
			Location: domain.Location{File: path, StartLine: line, StartCol: 1, EndLine: line, EndCol: 1},
		})
	}

	lines := strings.Split(string(src), "\n")
	hasUser, hasRunnable := false, false
	firstFrom := 0
	for i, line := range lines {
		n := i + 1
		if reUserInstr.MatchString(line) {
			hasUser = true
		}
		if reRunnable.MatchString(line) {
			hasRunnable = true
		}
		if firstFrom == 0 && regexp.MustCompile(`(?i)^\s*FROM\s`).MatchString(line) {
			firstFrom = n
		}
		if reFromLatest.MatchString(line) {
			add("docker:from-latest", "Base image pinned to :latest is non-reproducible; pin a specific version/digest.", domain.SevMinor, domain.TypeCodeSmell, n, 10)
		}
		if reCurlPipeSh.MatchString(line) {
			add("docker:curl-pipe-shell", "Piping a download into a shell in RUN executes unverified remote code; download, verify a checksum, then run.", domain.SevCritical, domain.TypeVulnerability, n, 20)
		}
		if reSudo.MatchString(line) {
			add("docker:run-sudo", "Avoid sudo in RUN; the build already runs as root, and sudo can behave unpredictably. Use USER instead.", domain.SevMinor, domain.TypeCodeSmell, n, 10)
		}
		if reAddInstr.MatchString(line) && !strings.Contains(strings.ToLower(line), "http") {
			add("docker:add-local", "Use COPY for local files; ADD has surprising behavior (auto-extract, URL fetch). Reserve ADD for remote/tar sources.", domain.SevMinor, domain.TypeCodeSmell, n, 5)
		}
	}
	if hasRunnable && !hasUser {
		ln := firstFrom
		if ln == 0 {
			ln = 1
		}
		add("docker:run-as-root", "No USER instruction: the container runs as root. Add a non-root USER for the runtime stage.", domain.SevMajor, domain.TypeHotspot, ln, 15)
	}
	return out
}

// DockerfileCatalog returns catalogue entries for the Dockerfile checks.
func DockerfileCatalog() []Meta {
	type d struct {
		id, name, desc, rem string
		sev                 domain.Severity
		typ                 domain.IssueType
		cwe                 []string
	}
	defs := []d{
		{"docker:from-latest", "Base image uses :latest", "A :latest base image is non-reproducible and silently changes.", "Pin a specific tag or digest (FROM image:1.2.3 or @sha256:...).", domain.SevMinor, domain.TypeCodeSmell, nil},
		{"docker:curl-pipe-shell", "Download piped into a shell in RUN", "Piping curl/wget into a shell runs unverified remote code at build time.", "Download to a file, verify a checksum/signature, then execute.", domain.SevCritical, domain.TypeVulnerability, []string{"CWE-494"}},
		{"docker:run-sudo", "sudo used in RUN", "sudo is unnecessary (the build runs as root) and can mask privilege intent.", "Remove sudo; switch users with the USER instruction.", domain.SevMinor, domain.TypeCodeSmell, nil},
		{"docker:add-local", "ADD used for local files", "ADD auto-extracts archives and can fetch URLs — surprising for local copies.", "Use COPY for local files; reserve ADD for remote/tar sources.", domain.SevMinor, domain.TypeCodeSmell, nil},
		{"docker:run-as-root", "Container runs as root (no USER)", "Without a USER instruction the container process runs as root.", "Add a non-root USER for the runtime stage.", domain.SevMajor, domain.TypeHotspot, []string{"CWE-250"}},
	}
	out := make([]Meta, 0, len(defs))
	for _, x := range defs {
		owasp := []string(nil)
		tags := []string{"docker"}
		if len(x.cwe) > 0 {
			tags = append(tags, "security")
		}
		out = append(out, Meta{
			ID: x.id, Name: x.name, Language: "docker", Type: x.typ, Severity: x.sev, EffortMin: 10,
			Description: x.desc, Remediation: x.rem, CWE: x.cwe, OWASP: owasp, Tags: tags,
		})
	}
	return out
}
