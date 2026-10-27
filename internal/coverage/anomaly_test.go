package coverage

import (
	"strings"
	"testing"
	"time"
)

func TestEvaluateFlagsSoftCrashAsDegraded(t *testing.T) {
	now := time.Now()
	records := []StageRecord{
		{StageID: "httpx_probe", Required: true, Status: StatusCompleted, OutputCount: 10},
		// Soft stage crashed (exit -1) — Required=false, so it never reaches
		// the RequiredIssues path, but the anomaly gate must catch it.
		{StageID: "waf_detect", Required: false, Status: StatusFailed, ExitCode: -1, Error: "scanner_exit"},
	}
	r := Evaluate("x.com", now, now, records)
	if r.Status != "DEGRADED" {
		t.Fatalf("status = %q, want DEGRADED", r.Status)
	}
	if !anyContains(r.Anomalies, "waf_detect crashed") {
		t.Errorf("anomalies missing crash note: %v", r.Anomalies)
	}
}

func TestEvaluateFlagsDeadURLSources(t *testing.T) {
	now := time.Now()
	records := []StageRecord{
		{StageID: "gau_urls", Required: false, Status: StatusCompletedEmpty, OutputCount: 0},
		{StageID: "wayback_urls", Required: false, Status: StatusCompletedEmpty, OutputCount: 0},
		{StageID: "katana_crawl", Required: false, Status: StatusCompleted, OutputCount: 400},
	}
	r := Evaluate("x.com", now, now, records)
	if r.Status != "DEGRADED" {
		t.Fatalf("status = %q, want DEGRADED", r.Status)
	}
	if !anyContains(r.Anomalies, "2 of 3 URL discovery sources returned 0") {
		t.Errorf("anomalies missing dead-source note: %v", r.Anomalies)
	}
}

func TestEvaluateCleanRunStaysComplete(t *testing.T) {
	now := time.Now()
	records := []StageRecord{
		{StageID: "gau_urls", Required: false, Status: StatusCompleted, OutputCount: 100},
		{StageID: "wayback_urls", Required: false, Status: StatusCompleted, OutputCount: 50},
		{StageID: "katana_crawl", Required: false, Status: StatusCompleted, OutputCount: 400},
		{StageID: "httpx_probe", Required: true, Status: StatusCompleted, OutputCount: 28},
	}
	r := Evaluate("x.com", now, now, records)
	if r.Status != "COMPLETE" {
		t.Fatalf("status = %q, want COMPLETE; anomalies=%v", r.Status, r.Anomalies)
	}
}

func anyContains(hay []string, needle string) bool {
	for _, h := range hay {
		if strings.Contains(h, needle) {
			return true
		}
	}
	return false
}
