// Package diffsnap implements run-over-run diffing for a target's work
// directory. After each scan it compares the current subdomain and
// JavaScript-asset inventories against the previous run's stored snapshot,
// writes "new_*" delta files plus a human- and machine-readable report, and
// then promotes the current inventory to be the baseline the next run diffs
// against.
//
// For a hunter the deltas are the highest-signal output: a subdomain or JS
// bundle that appeared since the last sweep is fresh, un-triaged attack
// surface. The full inventories still live in live_subs.txt / js_assets.txt;
// this package only answers "what changed".
package diffsnap

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// maxArchives bounds the per-run snapshot history kept under
// .rfuf/history/<timestamp>/ so a long-lived target directory does not grow
// without limit. The "latest" baseline is always retained separately.
const maxArchives = 10

// tracked describes one inventory file to diff across runs.
type tracked struct {
	// Label is the human name used in the report.
	Label string
	// Current is the inventory file produced by the current run, relative to
	// the work directory (e.g. "live_subs.txt").
	Current string
	// Delta is the file this package writes listing only entries that are new
	// since the previous run (e.g. "new_subdomains.txt").
	Delta string
}

var trackedArtifacts = []tracked{
	{Label: "subdomains", Current: "live_subs.txt", Delta: "new_subdomains.txt"},
	{Label: "js_assets", Current: "js_assets.txt", Delta: "new_js_assets.txt"},
}

// artifactDiff is the per-inventory result recorded in the report.
type artifactDiff struct {
	Label        string   `json:"label"`
	Source       string   `json:"source"`
	CurrentCount int      `json:"current_count"`
	NewCount     int      `json:"new_count"`
	RemovedCount int      `json:"removed_count"`
	New          []string `json:"new"`
	Removed      []string `json:"removed"`
}

// report is written to diff_report.json and summarized in diff_report.md.
type report struct {
	Timestamp           string         `json:"timestamp"`
	PreviousTimestamp   string         `json:"previous_timestamp"`
	BaselineEstablished bool           `json:"baseline_established"`
	Artifacts           []artifactDiff `json:"artifacts"`
}

type meta struct {
	Timestamp string `json:"timestamp"`
}

// Run performs the diff for workDir and updates the stored baseline. It never
// returns an error for a missing or empty inventory file — a target may not
// produce JS assets, and the first run has no baseline to compare against — so
// it is safe to wire as an optional pipeline stage.
func Run(workDir string) error {
	now := time.Now().UTC()
	stamp := now.Format("20060102T150405Z")

	historyDir := filepath.Join(workDir, ".rfuf", "history")
	latestDir := filepath.Join(historyDir, "latest")

	// A baseline exists only if the previous run wrote one. Its absence means
	// this is the first tracked run for the target: we establish the baseline
	// and report no deltas rather than flagging the entire inventory as "new".
	prev := readMeta(latestDir)
	firstRun := prev.Timestamp == ""

	rep := report{
		Timestamp:           stamp,
		PreviousTimestamp:   prev.Timestamp,
		BaselineEstablished: firstRun,
	}

	for _, art := range trackedArtifacts {
		current := readSet(filepath.Join(workDir, art.Current))
		baseline := readSet(filepath.Join(latestDir, art.Current))

		var added, removed []string
		if !firstRun {
			added = difference(current, baseline)
			removed = difference(baseline, current)
		}

		// Always materialize the delta file, empty on a first run or when
		// nothing changed, so downstream consumers can rely on its presence.
		if err := writeLines(filepath.Join(workDir, art.Delta), added); err != nil {
			return err
		}

		rep.Artifacts = append(rep.Artifacts, artifactDiff{
			Label:        art.Label,
			Source:       art.Current,
			CurrentCount: len(current),
			NewCount:     len(added),
			RemovedCount: len(removed),
			New:          added,
			Removed:      removed,
		})
	}

	if err := writeReports(workDir, rep); err != nil {
		return err
	}
	if err := promoteBaseline(workDir, historyDir, latestDir, stamp); err != nil {
		return err
	}
	printSummary(rep, firstRun)
	return nil
}

// readSet returns the sorted, de-duplicated, non-empty lines of a file. A
// missing or unreadable file yields an empty set.
func readSet(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		seen[line] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for line := range seen {
		out = append(out, line)
	}
	sort.Strings(out)
	return out
}

// difference returns the sorted elements of a that are not in b. Both inputs
// are assumed sorted and unique.
func difference(a, b []string) []string {
	bset := make(map[string]struct{}, len(b))
	for _, v := range b {
		bset[v] = struct{}{}
	}
	var out []string
	for _, v := range a {
		if _, ok := bset[v]; !ok {
			out = append(out, v)
		}
	}
	return out
}

func writeLines(path string, lines []string) error {
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0644)
}

func writeReports(workDir string, rep report) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(workDir, "diff_report.json"), append(data, '\n'), 0644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(workDir, "diff_report.md"), []byte(renderMarkdown(rep)), 0644)
}

func renderMarkdown(rep report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Run-over-run diff\n\n")
	fmt.Fprintf(&b, "- Snapshot: `%s`\n", rep.Timestamp)
	if rep.BaselineEstablished {
		fmt.Fprintf(&b, "- Baseline established on this run; no previous snapshot to diff against.\n\n")
	} else {
		fmt.Fprintf(&b, "- Previous: `%s`\n\n", rep.PreviousTimestamp)
	}
	for _, art := range rep.Artifacts {
		fmt.Fprintf(&b, "## %s\n\n", art.Label)
		fmt.Fprintf(&b, "- current: %d  |  new: %d  |  removed: %d\n\n", art.CurrentCount, art.NewCount, art.RemovedCount)
		if len(art.New) > 0 {
			fmt.Fprintf(&b, "**New since last run:**\n\n")
			for _, v := range art.New {
				fmt.Fprintf(&b, "- %s\n", v)
			}
			b.WriteByte('\n')
		}
		if len(art.Removed) > 0 {
			fmt.Fprintf(&b, "**Gone since last run:**\n\n")
			for _, v := range art.Removed {
				fmt.Fprintf(&b, "- %s\n", v)
			}
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// promoteBaseline copies the current inventories into .rfuf/history/latest/
// (the baseline the next run diffs against) and keeps a timestamped archive
// copy, pruning old archives beyond maxArchives.
func promoteBaseline(workDir, historyDir, latestDir, stamp string) error {
	archiveDir := filepath.Join(historyDir, stamp)
	for _, dir := range []string{latestDir, archiveDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	for _, art := range trackedArtifacts {
		data, err := os.ReadFile(filepath.Join(workDir, art.Current))
		if err != nil {
			// Nothing produced for this artifact this run; leave any prior
			// baseline in place rather than erasing it.
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if err := os.WriteFile(filepath.Join(latestDir, art.Current), data, 0644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(archiveDir, art.Current), data, 0644); err != nil {
			return err
		}
	}
	if err := writeMeta(latestDir, meta{Timestamp: stamp}); err != nil {
		return err
	}
	return pruneArchives(historyDir)
}

func pruneArchives(historyDir string) error {
	entries, err := os.ReadDir(historyDir)
	if err != nil {
		return err
	}
	var stamps []string
	for _, e := range entries {
		if e.IsDir() && e.Name() != "latest" {
			stamps = append(stamps, e.Name())
		}
	}
	if len(stamps) <= maxArchives {
		return nil
	}
	sort.Strings(stamps) // lexicographic == chronological for this stamp format
	for _, old := range stamps[:len(stamps)-maxArchives] {
		if err := os.RemoveAll(filepath.Join(historyDir, old)); err != nil {
			return err
		}
	}
	return nil
}

func readMeta(latestDir string) meta {
	data, err := os.ReadFile(filepath.Join(latestDir, "snapshot.json"))
	if err != nil {
		return meta{}
	}
	var m meta
	if err := json.Unmarshal(data, &m); err != nil {
		return meta{}
	}
	return m
}

func writeMeta(latestDir string, m meta) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(latestDir, "snapshot.json"), append(data, '\n'), 0644)
}

func printSummary(rep report, firstRun bool) {
	if firstRun {
		fmt.Println("[*] diff: baseline established (first tracked run; no deltas)")
		return
	}
	for _, art := range rep.Artifacts {
		fmt.Printf("[*] diff: %s +%d new / -%d removed (of %d)\n", art.Label, art.NewCount, art.RemovedCount, art.CurrentCount)
	}
}
