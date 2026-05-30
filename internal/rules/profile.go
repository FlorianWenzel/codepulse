package rules

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/FlorianWenzel/codepulse/internal/domain"
)

// Profile customizes the built-in rule set, like a SonarQube quality profile.
// It can disable rules and override their severities. The zero value (and a
// nil *Profile) is a no-op: every built-in rule is active at its default
// severity.
//
// Profile files are YAML (or JSON, which is valid YAML), e.g. .codepulse.yml:
//
//	disable:
//	  - js:var-declaration
//	  - go:todo-comment
//	severity:
//	  go:panic-usage: BLOCKER
//	  py:bare-except: MINOR
type Profile struct {
	Disable  []string          `yaml:"disable" json:"disable"`
	Severity map[string]string `yaml:"severity" json:"severity"`
}

// LoadProfile reads and validates a profile from a YAML/JSON file.
func LoadProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse profile %s: %w", path, err)
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("profile %s: %w", path, err)
	}
	return &p, nil
}

var validSeverities = map[string]bool{
	string(domain.SevBlocker): true, string(domain.SevCritical): true,
	string(domain.SevMajor): true, string(domain.SevMinor): true,
	string(domain.SevInfo): true,
}

// validate rejects unknown rule ids (typos) and invalid severities so a broken
// profile fails loudly instead of silently doing nothing.
func (p *Profile) validate() error {
	known := map[string]bool{}
	for _, m := range Catalog() {
		known[m.ID] = true
	}
	for _, id := range p.Disable {
		if !known[id] {
			return fmt.Errorf("unknown rule id %q in disable", id)
		}
	}
	for id, sev := range p.Severity {
		if !known[id] {
			return fmt.Errorf("unknown rule id %q in severity", id)
		}
		if !validSeverities[sev] {
			return fmt.Errorf("invalid severity %q for rule %q (want BLOCKER|CRITICAL|MAJOR|MINOR|INFO)", sev, id)
		}
	}
	return nil
}

// Apply returns a copy of rs with disabled rules removed and severities
// overridden per the profile. A nil profile returns rs unchanged.
func (p *Profile) Apply(rs []Rule) []Rule {
	if p == nil || (len(p.Disable) == 0 && len(p.Severity) == 0) {
		return rs
	}
	disabled := make(map[string]bool, len(p.Disable))
	for _, id := range p.Disable {
		disabled[id] = true
	}
	out := make([]Rule, 0, len(rs))
	for _, r := range rs {
		if disabled[r.ID] {
			continue
		}
		if sev, ok := p.Severity[r.ID]; ok {
			r.Severity = domain.Severity(sev)
		}
		out = append(out, r)
	}
	return out
}
