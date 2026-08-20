package owasp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/CyberShuriken/rfuf/internal/coverage"
	"github.com/CyberShuriken/rfuf/internal/evidence"
)

type Category struct {
	ID     string
	Name   string
	Stages []string
	Manual string
	Inputs []string
}

type Candidate struct {
	ID              string `json:"id"`
	OWASP           string `json:"owasp"`
	Category        string `json:"category"`
	Source          string `json:"source"`
	Target          string `json:"target,omitempty"`
	Severity        string `json:"severity"`
	Confidence      string `json:"confidence"`
	ValidationState string `json:"validation_state"`
	Instruction     string `json:"instruction"`
}

type categoryResult struct {
	Category
	Status     string
	Artifacts  []string
	Candidates int
	Reason     string
}

var categories = []Category{
	{ID: "A01:2025", Name: "Broken Access Control", Stages: []string{"idor_surface_run", "idor_scan", "manual_review_queue", "nuclei_auth_scan"}, Inputs: []string{"all_urls.txt", "idor_surface.txt", "bola_targets.txt"}, Manual: "Use two authorized accounts or roles. Replay the same request with a synthetic object owned by the other account and verify an explicit denial with no data disclosure."},
	{ID: "A02:2025", Name: "Security Misconfiguration", Stages: []string{"nuclei_misconfigs", "secheaders_run", "backupscan_run", "cors2_run", "hostheader_run", "bucket_guess_run", "takeover_v2_run"}, Inputs: []string{"misconfigs.txt", "secheaders_findings.txt", "backupscan_findings.txt"}, Manual: "Review exposed panels, default settings, verbose errors, headers, cloud permissions, TLS, and deployment configuration using the authorized test environment."},
	{ID: "A03:2025", Name: "Software Supply Chain Failures", Stages: nil, Inputs: []string{"go.mod", "package-lock.json", "Dockerfile", ".github/workflows"}, Manual: "Provide repository, lockfiles, SBOM, CI workflows, and release metadata. Review dependency provenance, pinning, signed artifacts, and third-party action trust."},
	{ID: "A04:2025", Name: "Cryptographic Failures", Stages: []string{"authshape_run", "nuclei_auth_scan", "js_mine_run"}, Inputs: []string{"authshape_findings.txt", "js_mine_findings.txt"}, Manual: "Review TLS, key storage, token signing and rotation, password hashing, encryption at rest, randomness, and sensitive-data minimization."},
	{ID: "A05:2025", Name: "Injection", Stages: []string{"sqlmap_scan", "ghauri_sqli", "xss_scan", "rce_scan", "ssrf_scan", "lfi_scan", "reflection_run", "paramshape_run"}, Inputs: []string{"sqlmap_results", "ghauri_results.txt", "xss_vulnerabilities.txt"}, Manual: "Retest only the candidate parameter in a controlled account or local replica. Use non-destructive proofs and stop before data modification or extraction."},
	{ID: "A06:2025", Name: "Insecure Design", Stages: []string{"businesslogic_run", "race_scan", "manual_review_queue"}, Inputs: []string{"business_logic_findings.txt", "race_candidates.txt", "manual_business_logic_review.txt"}, Manual: "Document the intended business invariant, then test authorization, limits, approval, replay, rollback, and state transitions with synthetic data."},
	{ID: "A07:2025", Name: "Authentication Failures", Stages: []string{"authshape_run", "nuclei_auth_scan", "signup_takeover_run", "oauth_audit_run"}, Inputs: []string{"authshape_findings.txt", "auth_results.txt", "signup_takeover_findings.txt"}, Manual: "Test MFA, reset and recovery, session rotation, logout invalidation, rate limits, enumeration, OAuth state/PKCE, and token expiry with authorized test identities."},
	{ID: "A08:2025", Name: "Software or Data Integrity Failures", Stages: []string{"backupscan_run", "js_mine_run", "signup_takeover_run"}, Inputs: []string{"backupscan_findings.txt", "js_mine_findings.txt"}, Manual: "Review signed updates, webhook verification, deserialization, CI/CD artifact integrity, tamper detection, and transaction rollback."},
	{ID: "A09:2025", Name: "Security Logging and Alerting Failures", Stages: nil, Inputs: []string{"audit.log", "security-events"}, Manual: "Trigger safe events in a test tenant and verify actor, timestamp, correlation, alerting, retention, access control, and tamper resistance."},
	{ID: "A10:2025", Name: "Mishandling of Exceptional Conditions", Stages: []string{"race_scan", "paramshape_run", "businesslogic_run"}, Inputs: []string{"race_candidates.txt", "paramshape_findings.txt", "business_logic_findings.txt"}, Manual: "Test fail-open authorization, partial failures, rollback, retry/idempotency, malformed input, resource limits, and state consistency without destructive actions."},
}

var owaspByCategory = map[string]string{
	"idor": "A01:2025", "idor_surface": "A01:2025", "bola": "A01:2025", "auth": "A07:2025",
	"subdomain_takeover": "A02:2025", "cors": "A02:2025", "security_headers": "A02:2025", "backup_exposure": "A02:2025", "host_header": "A02:2025", "cloud_bucket": "A02:2025",
	"secret_exposure": "A04:2025", "jwt": "A04:2025", "sqli": "A05:2025", "xss": "A05:2025", "rce": "A05:2025", "ssrf": "A05:2025", "lfi": "A05:2025", "reflection": "A05:2025", "paramshape": "A05:2025",
	"business_logic": "A06:2025", "race": "A06:2025", "oauth": "A07:2025", "signup_takeover": "A07:2025", "open_redirect": "A07:2025",
}

func Generate(workDir, domain string, report coverage.CoverageReport, stageRecords []coverage.StageRecord, evidenceRecords []evidence.Record) error {
	candidates := make([]Candidate, 0, len(evidenceRecords)+64)
	for i, record := range evidenceRecords {
		owaspID := owaspByCategory[strings.ToLower(record.Category)]
		if owaspID == "" {
			continue
		}
		candidates = append(candidates, Candidate{ID: fmt.Sprintf("RFUF-%04d", i+1), OWASP: owaspID, Category: record.Category, Source: record.EvidenceRef, Target: record.Target, Severity: record.Severity, Confidence: record.Confidence, ValidationState: "candidate", Instruction: instructionFor(owaspID)})
	}
	for _, source := range []string{"idor_surface.txt", "bola_targets.txt", "bola_permutations.txt", "manual_business_logic_review.txt", "oauth_findings.txt", "race_candidates.txt"} {
		more, err := candidatesFromFile(workDir, source, len(candidates)+1)
		if err != nil {
			return err
		}
		candidates = append(candidates, more...)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].OWASP != candidates[j].OWASP {
			return candidates[i].OWASP < candidates[j].OWASP
		}
		return candidates[i].Source < candidates[j].Source
	})
	if err := writeCandidates(workDir, candidates); err != nil {
		return err
	}
	results := evaluateCategories(workDir, report, stageRecords, candidates)
	if err := writeCoverage(workDir, domain, report, results); err != nil {
		return err
	}
	return writeManualPlan(workDir, domain, results, candidates)
}

func instructionFor(id string) string {
	for _, category := range categories {
		if category.ID == id {
			return category.Manual
		}
	}
	return "Manually validate this candidate in an authorized test environment and record the expected control and observed result."
}

func candidatesFromFile(workDir, name string, start int) ([]Candidate, error) {
	file, err := os.Open(filepath.Join(workDir, name))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	category := ""
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "idor") || strings.Contains(lower, "bola"):
		category = "A01:2025"
	case strings.Contains(lower, "business") || strings.Contains(lower, "race"):
		category = "A06:2025"
	case strings.Contains(lower, "oauth"):
		category = "A07:2025"
	default:
		return nil, nil
	}
	var out []Candidate
	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		line++
		value := redactLine(scanner.Text())
		if strings.TrimSpace(value) == "" {
			continue
		}
		target := extractURL(value)
		out = append(out, Candidate{ID: fmt.Sprintf("RFUF-%04d", start+len(out)), OWASP: category, Category: strings.TrimSuffix(name, filepath.Ext(name)), Source: fmt.Sprintf("%s:%d", name, line), Target: target, Severity: "medium", Confidence: "candidate", ValidationState: "needs-auth-validation", Instruction: instructionFor(category)})
	}
	return out, scanner.Err()
}

func redactLine(line string) string {
	for _, key := range []string{"cookie", "authorization", "bearer", "token", "secret", "apikey", "api_key", "password"} {
		lower := strings.ToLower(line)
		if idx := strings.Index(lower, key+"="); idx >= 0 {
			return line[:idx] + key + "=<redacted>"
		}
	}
	return line
}

func extractURL(line string) string {
	for _, field := range strings.Fields(line) {
		if strings.HasPrefix(field, "http://") || strings.HasPrefix(field, "https://") {
			if parsed, err := url.Parse(strings.Trim(field, "()[],;")); err == nil {
				parsed.User = nil
				return parsed.String()
			}
		}
	}
	return ""
}

func writeCandidates(workDir string, candidates []Candidate) error {
	file, err := os.Create(filepath.Join(workDir, "candidate_index.jsonl"))
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	for _, candidate := range candidates {
		if err := encoder.Encode(candidate); err != nil {
			return err
		}
	}
	return nil
}

func evaluateCategories(workDir string, report coverage.CoverageReport, records []coverage.StageRecord, candidates []Candidate) []categoryResult {
	stageStatus := make(map[string]coverage.StageStatus, len(records))
	for _, record := range records {
		stageStatus[record.StageID] = record.Status
	}
	result := make([]categoryResult, 0, len(categories))
	for _, category := range categories {
		count := 0
		for _, candidate := range candidates {
			if candidate.OWASP == category.ID {
				count++
			}
		}
		if len(category.Stages) == 0 {
			result = append(result, categoryResult{Category: category, Status: "blocked", Candidates: count, Reason: "requires source, deployment, workflow, or observability input not available to a black-box domain scan"})
			continue
		}
		blocked := ""
		completed := 0
		for _, stage := range category.Stages {
			switch stageStatus[stage] {
			case coverage.StatusFailed, coverage.StatusTimedOut, coverage.StatusBlocked, coverage.StatusSkipped:
				blocked = string(stageStatus[stage])
			case coverage.StatusCompleted, coverage.StatusCompletedEmpty:
				completed++
			}
		}
		status := "partial"
		reason := "automation completed, but manual validation or additional context is required"
		if blocked != "" {
			status = "blocked"
			reason = "one or more relevant stages are " + blocked
		} else if completed == len(category.Stages) && count == 0 {
			status = "covered"
			reason = "all mapped stages completed; no candidate evidence was recorded"
		}
		artifacts := existingArtifacts(workDir, category.Inputs)
		result = append(result, categoryResult{Category: category, Status: status, Artifacts: artifacts, Candidates: count, Reason: reason})
	}
	return result
}

func existingArtifacts(workDir string, paths []string) []string {
	var out []string
	for _, path := range paths {
		if _, err := os.Stat(filepath.Join(workDir, path)); err == nil {
			out = append(out, path)
		}
	}
	return out
}

func writeCoverage(workDir, domain string, report coverage.CoverageReport, results []categoryResult) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# OWASP Top 10:2025 Coverage\n\n**Domain:** `%s`  \n**Pipeline status:** **%s**  \n**Stages:** %d total, %d completed, %d completed-empty, %d failed, %d timed out, %d skipped, %d blocked\n\n", domain, report.Status, report.TotalStages, report.CompletedStages, report.EmptyStages, report.FailedStages, report.TimedOutStages, report.SkippedStages, report.BlockedStages)
	b.WriteString("This is an evidence and coverage report, not a guarantee that the target is secure. `covered` means the mapped automated stages completed; `partial` means manual validation or additional context is required; `blocked` means the required input or stage was unavailable.\n\n")
	b.WriteString("| Category | Status | Candidates | Artifacts | Reason |\n|---|---|---:|---|---|\n")
	for _, item := range results {
		fmt.Fprintf(&b, "| %s %s | **%s** | %d | %s | %s |\n", item.ID, item.Name, item.Status, item.Candidates, strings.Join(item.Artifacts, ", "), item.Reason)
	}
	b.WriteString("\n## Required inputs that were not supplied\n\nA03, A09, and parts of A04, A06, A07, A08, and A10 require repository, deployment, identity, business-workflow, or logging access. See [MANUAL_TEST_PLAN.md](./MANUAL_TEST_PLAN.md) for exact next steps.\n")
	return os.WriteFile(filepath.Join(workDir, "OWASP_2025_COVERAGE.md"), []byte(b.String()), 0644)
}

func writeManualPlan(workDir, domain string, results []categoryResult, candidates []Candidate) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Manual Test Plan\n\n**Domain:** `%s`\n\n", domain)
	b.WriteString("Run these tasks only against explicitly authorized assets and dedicated test data. Redact credentials and personal data. Do not continue when a task would read, modify, delete, transfer, or expose real-user or financial data.\n\n")
	b.WriteString("## Candidate-specific tasks\n\n")
	if len(candidates) == 0 {
		b.WriteString("No candidate records were produced. Review the coverage report for categories that were blocked or completed with empty input.\n\n")
	} else {
		for _, candidate := range candidates {
			fmt.Fprintf(&b, "### %s — %s\n\n", candidate.ID, candidate.OWASP)
			fmt.Fprintf(&b, "| Field | Value |\n|---|---|\n| Category | %s |\n| Source | `%s` |\n| Target | `%s` |\n| Severity suggestion | %s |\n| Confidence | %s |\n| Validation state | %s |\n| Required control | %s |\n\n", candidate.Category, candidate.Source, candidate.Target, candidate.Severity, candidate.Confidence, candidate.ValidationState, candidate.Instruction)
			b.WriteString("**Evidence to capture:** redacted request method and path, status code, response schema or safe summary, test identity/role, object ownership, and timestamp.\n\n**Stop condition:** stop if the response contains data outside the dedicated test account, or if the action is destructive or financially consequential.\n\n")
		}
	}
	b.WriteString("## Category-level tasks\n\n")
	for _, item := range results {
		if item.Status == "covered" && item.Candidates == 0 {
			continue
		}
		fmt.Fprintf(&b, "### %s %s — %s\n\n%s\n\n", item.ID, item.Name, item.Status, item.Manual)
	}
	return os.WriteFile(filepath.Join(workDir, "MANUAL_TEST_PLAN.md"), []byte(b.String()), 0644)
}
