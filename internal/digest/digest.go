// Package digest consolidates a run's scattered per-tool output files into a
// single machine-readable findings.json, and exposes the same data as a Go
// struct so the notifier can summarize a run without re-reading every file.
//
// A bug-bounty run leaves dozens of *.txt result files behind; triage tooling
// and alerts want one structured view: how many findings of each class, a few
// samples, and the fresh attack surface (new subdomains / JS) from the
// run-over-run diff. That is exactly what Build produces.
package digest

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// maxSamples bounds how many example lines are embedded per category so the
// digest and any notification stay compact regardless of result volume.
const maxSamples = 10

// source names a result file, the finding class it represents, and a coarse
// severity used for ordering and alert emphasis.
type source struct {
	Category string
	File     string
	Severity string // CRITICAL | HIGH | MEDIUM | LOW | INFO
}

// coreSources are the primary scanner outputs with hand-assigned severities.
// Finder outputs (*_findings.txt) are discovered dynamically in Build so new
// finders are picked up without editing this list.
var coreSources = []source{
	{"subdomain_takeover", "validated_takeovers.txt", "HIGH"},
	{"exposed_credentials", "credentials_found.txt", "CRITICAL"},
	{"rce", "nuclei_rce_rce.txt", "CRITICAL"},
	{"ssrf", "ssrf_vulnerabilities.txt", "HIGH"},
	{"idor", "idor_vulnerabilities.txt", "HIGH"},
	{"xss", "xss_vulnerabilities.txt", "HIGH"},
	{"lfi", "lfi_results.txt", "HIGH"},
	{"auth", "auth_results.txt", "HIGH"},
	{"open_redirect", "open_redirect_results.txt", "MEDIUM"},
	{"cors", "cors_findings.txt", "MEDIUM"},
	{"graphql_exposed", "graphql_exposed.txt", "MEDIUM"},
	{"misconfig", "misconfigs.txt", "MEDIUM"},
	{"secrets", "potential_secrets.txt", "MEDIUM"},
}

// Category is a per-class result summary in the digest.
type Category struct {
	Name     string   `json:"name"`
	Severity string   `json:"severity"`
	File     string   `json:"file"`
	Count    int      `json:"count"`
	Samples  []string `json:"samples,omitempty"`
}

// Digest is the consolidated view of one run, written to findings.json.
type Digest struct {
	GeneratedAt   string     `json:"generated_at"`
	Domain        string     `json:"domain"`
	TotalFindings int        `json:"total_findings"`
	NewSubdomains []string   `json:"new_subdomains"`
	NewJSAssets   []string   `json:"new_js_assets"`
	Findings      []Category `json:"findings"`
}

// severityRank orders categories most-severe first in the output.
var severityRank = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

// Build scans workDir, writes findings.json, and returns the digest. It is
// tolerant of missing files (a run may not produce every artifact) and never
// fails on an empty workspace.
func Build(workDir, domain string) (Digest, error) {
	d := Digest{
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Domain:        domain,
		NewSubdomains: readLines(filepath.Join(workDir, "new_subdomains.txt")),
		NewJSAssets:   readLines(filepath.Join(workDir, "new_js_assets.txt")),
	}

	seen := map[string]bool{}
	add := func(src source) {
		if seen[src.File] {
			return
		}
		lines := readLines(filepath.Join(workDir, src.File))
		if len(lines) == 0 {
			return
		}
		seen[src.File] = true
		cat := Category{Name: src.Category, Severity: src.Severity, File: src.File, Count: len(lines)}
		if len(lines) > maxSamples {
			cat.Samples = append(cat.Samples, lines[:maxSamples]...)
		} else {
			cat.Samples = append(cat.Samples, lines...)
		}
		d.Findings = append(d.Findings, cat)
		d.TotalFindings += len(lines)
	}

	for _, src := range coreSources {
		add(src)
	}
	// Pick up every finder's *_findings.txt generically so new finders are
	// covered without changing this file. These are MEDIUM by default.
	for _, match := range glob(workDir, "*_findings.txt") {
		base := filepath.Base(match)
		add(source{Category: strings.TrimSuffix(base, "_findings.txt"), File: base, Severity: "MEDIUM"})
	}

	sort.SliceStable(d.Findings, func(i, j int) bool {
		return severityRank[d.Findings[i].Severity] < severityRank[d.Findings[j].Severity]
	})

	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return d, err
	}
	if err := os.WriteFile(filepath.Join(workDir, "findings.json"), append(data, '\n'), 0644); err != nil {
		return d, err
	}
	return d, nil
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func glob(workDir, pattern string) []string {
	matches, err := filepath.Glob(filepath.Join(workDir, pattern))
	if err != nil {
		return nil
	}
	sort.Strings(matches)
	return matches
}
