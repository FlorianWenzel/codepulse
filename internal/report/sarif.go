package report

import (
	"encoding/json"
	"io"

	"github.com/FlorianWenzel/codepulse/internal/domain"
)

// Minimal SARIF 2.1.0 structures — enough to be consumed by GitHub code
// scanning, IDEs, and other SARIF readers.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifText         `json:"shortDescription"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine"`
	EndColumn   int `json:"endColumn"`
}

// sarifLevel maps a CodePulse severity to a SARIF level.
func sarifLevel(s domain.Severity) string {
	switch s {
	case domain.SevBlocker, domain.SevCritical:
		return "error"
	case domain.SevMajor, domain.SevMinor:
		return "warning"
	default:
		return "note"
	}
}

// RuleMeta is the minimal rule metadata SARIF needs in its driver section.
type RuleMeta struct {
	ID, Name string
	Type     domain.IssueType
	Severity domain.Severity
}

// WriteSARIF writes the report as SARIF 2.1.0. ruleMeta supplies the rule
// descriptors for the run's tool driver.
func WriteSARIF(w io.Writer, r domain.Report, ruleMeta []RuleMeta) error {
	rules := make([]sarifRule, 0, len(ruleMeta))
	for _, m := range ruleMeta {
		rules = append(rules, sarifRule{
			ID:               m.ID,
			Name:             m.Name,
			ShortDescription: sarifText{Text: m.Name},
			Properties: map[string]string{
				"type":     string(m.Type),
				"severity": string(m.Severity),
			},
		})
	}

	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: f.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.Location.File},
					Region: sarifRegion{
						StartLine:   f.Location.StartLine,
						StartColumn: f.Location.StartCol,
						EndLine:     f.Location.EndLine,
						EndColumn:   f.Location.EndCol,
					},
				},
			}},
		})
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           r.Tool,
				Version:        r.Version,
				InformationURI: "https://github.com/FlorianWenzel/codepulse",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
