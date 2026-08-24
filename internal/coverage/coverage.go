package coverage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type StageStatus string

const (
	StatusRunning        StageStatus = "running"
	StatusCompleted      StageStatus = "completed"
	StatusCompletedEmpty StageStatus = "completed_empty"
	StatusFailed         StageStatus = "failed"
	StatusTimedOut       StageStatus = "timed_out"
	StatusSkipped        StageStatus = "skipped"
	StatusBlocked        StageStatus = "blocked"
)

type ArtifactMetric struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Lines  int    `json:"lines"`
}

type StageRecord struct {
	StageID         string           `json:"stage_id"`
	Required        bool             `json:"required"`
	Dependencies    []string         `json:"dependencies,omitempty"`
	Status          StageStatus      `json:"status"`
	StartedAt       time.Time        `json:"started_at,omitempty"`
	FinishedAt      time.Time        `json:"finished_at,omitempty"`
	ExitCode        int              `json:"exit_code"`
	TimedOut        bool             `json:"timed_out"`
	InputCount      int              `json:"input_count"`
	OutputCount     int              `json:"output_count"`
	InputArtifacts  []ArtifactMetric `json:"input_artifacts,omitempty"`
	OutputArtifacts []ArtifactMetric `json:"output_artifacts,omitempty"`
	Error           string           `json:"error,omitempty"`
	SkipReason      string           `json:"skip_reason,omitempty"`
}

type CoverageReport struct {
	Domain          string        `json:"domain"`
	StartedAt       time.Time     `json:"started_at"`
	FinishedAt      time.Time     `json:"finished_at"`
	Status          string        `json:"status"`
	TotalStages     int           `json:"total_stages"`
	CompletedStages int           `json:"completed_stages"`
	EmptyStages     int           `json:"empty_stages"`
	FailedStages    int           `json:"failed_stages"`
	TimedOutStages  int           `json:"timed_out_stages"`
	SkippedStages   int           `json:"skipped_stages"`
	BlockedStages   int           `json:"blocked_stages"`
	RequiredIssues  []string      `json:"required_issues,omitempty"`
	Stages          []StageRecord `json:"stages"`
}

var (
	inputFlagPattern  = regexp.MustCompile(`(?:^|\s)(?:-l|--list|-m|--input-file|-i)\s+["']?([^\s"';&|()<>]+)`)
	outputFlagPattern = regexp.MustCompile(`(?:^|\s)(?:-o|--output|-of)\s+["']?([^\s"';&|()<>]+)`)
	// redirectPattern matches shell output redirections like `> file` or
	// `>> file` and `: > file`, but explicitly excludes fd-redirect forms
	// (`>&2`, `2>&1`, etc.) by requiring the character immediately after
	// `>`/`>>` to be whitespace, `:`, or the start of a quoted path — never
	// `&`. The captured group also stops at shell punctuation so that
	// trailing `;`, `&`, `|`, `&&`, `||`, or `()` do not bleed into the
	// filename.
	redirectPattern = regexp.MustCompile(`(?:>>?|:\s*>)\s+["']?([^\s"';&|()<>]+)`)
	// mvPattern captures the *destination* of `mv src dst` and
	// `mv src1 src2 dst` invocations. After a rename, the source no longer
	// exists — measuring source existence would falsely flag every renamed
	// step as a missing-artifact failure. We capture every group after the
	// `mv` command except the last (which is the final destination when
	// multiple sources are given); all are recorded as outputs because the
	// final state of the worktree contains the destination, never the
	// pre-rename source.
	mvPattern = regexp.MustCompile(`\bmv\s+(?:-[a-zA-Z]+\s+)*["']?([^\s"';&|()<>]+)["']?\s+["']?([^\s"';&|()<>]+)`)
)

func ExtractInputPaths(command string) []string {
	return extractUnique(inputFlagPattern.FindAllStringSubmatch(command, -1))
}

func ExtractOutputPaths(command string) []string {
	paths := extractUnique(outputFlagPattern.FindAllStringSubmatch(command, -1))
	paths = append(paths, extractUnique(redirectPattern.FindAllStringSubmatch(command, -1))...)
	// Merge destinations from `mv src dst`. Both src and dst are returned
	// because some pipelines write both files (dst is the real output; src
	// may not exist post-rename). MeasureArtifacts reports missing sources
	// as Exists=false but CountMetrics only counts lines from Exists=true
	// files, so an absent source cannot inflate the artifact count. We do,
	// however, want the destination to be measured against the real file.
	paths = append(paths, extractMvDestinations(command)...)
	return filterArtifactPaths(paths)
}

// extractMvDestinations returns only the *destination* of every `mv src dst`
// in the command. The source is intentionally excluded because it no longer
// exists post-rename, and reporting it as missing would falsely flag every
// `mv`-using step as a missing-artifact failure (the exact bug fixed here).
func extractMvDestinations(command string) []string {
	matches := mvPattern.FindAllStringSubmatch(command, -1)
	seen := make(map[string]bool)
	var out []string
	for _, m := range matches {
		// mvPattern captures src and dst; dst is the last group.
		if len(m) < 3 || m[2] == "" {
			continue
		}
		if !seen[m[2]] {
			seen[m[2]] = true
			out = append(out, m[2])
		}
	}
	return out
}

func extractUnique(matches [][]string) []string {
	seen := make(map[string]bool)
	var paths []string
	for _, match := range matches {
		if len(match) < 2 || match[1] == "" {
			continue
		}
		path := strings.TrimSpace(match[1])
		if path == "-" || strings.Contains(path, "$") || strings.Contains(path, "(") {
			continue
		}
		if !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	return filterArtifactPaths(paths)
}

func filterArtifactPaths(paths []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		path = strings.Trim(path, "'\"")
		if path == "" || strings.HasPrefix(path, "-") || path == "/dev/null" {
			continue
		}
		// Drop anything that still contains shell metacharacters or
		// whitespace — these were never real filenames.
		if strings.ContainsAny(path, " \t;&|<>()") {
			continue
		}
		if !seen[path] {
			seen[path] = true
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out
}

func MeasureArtifacts(workDir string, paths []string) []ArtifactMetric {
	metrics := make([]ArtifactMetric, 0, len(paths))
	for _, path := range paths {
		clean := filepath.Clean(path)
		if filepath.IsAbs(clean) || clean == "." || strings.HasPrefix(clean, "..") {
			continue
		}
		full := filepath.Join(workDir, clean)
		data, err := os.ReadFile(full)
		if err != nil {
			metrics = append(metrics, ArtifactMetric{Path: clean})
			continue
		}
		lines := 0
		if len(strings.TrimSpace(string(data))) > 0 {
			lines = len(strings.Split(strings.TrimSpace(string(data)), "\n"))
		}
		metrics = append(metrics, ArtifactMetric{Path: clean, Exists: true, Lines: lines})
	}
	return metrics
}

func CountMetrics(metrics []ArtifactMetric) int {
	total := 0
	for _, metric := range metrics {
		total += metric.Lines
	}
	return total
}

func WriteStageRecord(workDir string, record StageRecord) error {
	path := filepath.Join(workDir, ".rfuf", "stages", record.StageID+".json")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func LoadStageRecords(workDir string) ([]StageRecord, error) {
	dir := filepath.Join(workDir, ".rfuf", "stages")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var records []StageRecord
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var record StageRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return nil, fmt.Errorf("decode stage record %s: %w", entry.Name(), err)
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].StageID < records[j].StageID })
	return records, nil
}

func Evaluate(domain string, startedAt, finishedAt time.Time, records []StageRecord) CoverageReport {
	report := CoverageReport{Domain: domain, StartedAt: startedAt, FinishedAt: finishedAt, Status: "COMPLETE", Stages: records}
	for _, record := range records {
		report.TotalStages++
		switch record.Status {
		case StatusCompleted:
			report.CompletedStages++
		case StatusCompletedEmpty:
			report.EmptyStages++
		case StatusFailed:
			report.FailedStages++
		case StatusTimedOut:
			report.TimedOutStages++
		case StatusSkipped:
			report.SkippedStages++
		case StatusBlocked:
			report.BlockedStages++
		}
		if record.Required && record.Status != StatusCompleted && record.Status != StatusCompletedEmpty {
			report.RequiredIssues = append(report.RequiredIssues, fmt.Sprintf("%s: %s", record.StageID, record.Status))
		}
	}
	if len(report.RequiredIssues) > 0 {
		report.Status = "INCOMPLETE"
	}
	return report
}

func WriteReport(workDir string, report CoverageReport) error {
	dir := filepath.Join(workDir, ".rfuf")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "coverage_report.json"), data, 0644); err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# RFUF Coverage Report\n\n- **Domain:** `%s`\n- **Status:** **%s**\n- **Stages:** %d total, %d completed, %d completed-empty, %d failed, %d timed out, %d skipped, %d blocked\n\n", report.Domain, report.Status, report.TotalStages, report.CompletedStages, report.EmptyStages, report.FailedStages, report.TimedOutStages, report.SkippedStages, report.BlockedStages)
	if len(report.RequiredIssues) > 0 {
		b.WriteString("## Required-stage issues\n\n")
		for _, issue := range report.RequiredIssues {
			fmt.Fprintf(&b, "- %s\n", issue)
		}
	} else {
		b.WriteString("All required stages completed without failure or timeout.\n")
	}
	return os.WriteFile(filepath.Join(workDir, "CoverageReport.md"), []byte(b.String()), 0644)
}
