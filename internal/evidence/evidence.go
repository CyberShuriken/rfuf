package evidence

import (
	"bufio"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Record struct {
	Category        string `json:"category"`
	SourceStage     string `json:"source_stage"`
	Target          string `json:"target,omitempty"`
	Severity        string `json:"severity"`
	Confidence      string `json:"confidence"`
	ValidationState string `json:"validation_state"`
	EvidenceRef     string `json:"evidence_ref"`
	Line            int    `json:"line"`
}

var urlPattern = regexp.MustCompile(`https?://[^\s\]>)"']+`)

var artifactCategories = map[string]struct {
	Category string
	Severity string
}{
	"validated_takeovers.txt":      {"subdomain_takeover", "high"},
	"nuclei_rce_rce.txt":           {"rce", "critical"},
	"sqlmap_results":               {"sqli", "high"},
	"ghauri_results.txt":           {"sqli", "high"},
	"xss_vulnerabilities.txt":      {"xss", "medium"},
	"ssrf_vulnerabilities.txt":     {"ssrf", "high"},
	"idor_vulnerabilities.txt":     {"idor", "high"},
	"auth_results.txt":             {"auth", "high"},
	"cors_findings.txt":            {"cors", "medium"},
	"trufflehog_results.txt":       {"secret_exposure", "high"},
	"potential_secrets.txt":        {"secret_exposure", "high"},
	"js_secrets.txt":               {"secret_exposure", "high"},
	"open_redirect_results.txt":    {"open_redirect", "medium"},
	"lfi_results.txt":              {"lfi", "high"},
	"reflection_findings.txt":      {"reflection", "medium"},
	"paramshape_findings.txt":      {"paramshape", "medium"},
	"authshape_findings.txt":       {"auth", "medium"},
	"signup_takeover_findings.txt": {"signup_takeover", "high"},
	"oauth_findings.txt":           {"oauth", "high"},
	"race_results.txt":             {"race", "high"},
	"bucket_findings.txt":          {"cloud_bucket", "high"},
	"takeover_v2_findings.txt":     {"subdomain_takeover", "high"},
	"js_mine_findings.txt":         {"secret_exposure", "high"},
	"secheaders_findings.txt":      {"security_headers", "medium"},
	"backupscan_findings.txt":      {"backup_exposure", "high"},
	"business_logic_findings.txt":  {"business_logic", "medium"},
	"hostheader_findings.txt":      {"host_header", "high"},
	"cors2_findings.txt":           {"cors", "high"},
}

func BuildIndex(workDir string) ([]Record, error) {
	var records []Record
	for name, meta := range artifactCategories {
		path := filepath.Join(workDir, name)
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			entries, _ := os.ReadDir(path)
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				part, err := readArtifact(filepath.Join(path, entry.Name()), filepath.Join(name, entry.Name()), meta.Category, meta.Severity)
				if err != nil {
					return nil, err
				}
				records = append(records, part...)
			}
			continue
		}
		part, err := readArtifact(path, name, meta.Category, meta.Severity)
		if err != nil {
			return nil, err
		}
		records = append(records, part...)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Category != records[j].Category {
			return records[i].Category < records[j].Category
		}
		return records[i].EvidenceRef < records[j].EvidenceRef
	})
	return records, nil
}

func readArtifact(path, ref, category, severity string) ([]Record, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var records []Record
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		target := ""
		if match := urlPattern.FindString(line); match != "" {
			if parsed, err := url.Parse(match); err == nil {
				parsed.User = nil
				target = parsed.String()
			}
		}
		records = append(records, Record{Category: category, SourceStage: "artifact", Target: target, Severity: severity, Confidence: "candidate", ValidationState: "candidate", EvidenceRef: ref, Line: lineNumber})
	}
	return records, scanner.Err()
}

func WriteIndex(workDir string, records []Record) error {
	file, err := os.Create(filepath.Join(workDir, "evidence.jsonl"))
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			return err
		}
	}
	return nil
}
