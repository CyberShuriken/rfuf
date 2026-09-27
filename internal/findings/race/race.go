// Package race identifies business-logic endpoints for manual race testing.
// It deliberately sends no requests: race-condition validation can alter
// balances, orders, votes, and other application state.
package race

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

var raceKeywords = []struct{ kw, hint string }{
	{"coupon", "coupon-redemption double-spend"}, {"redeem", "redemption double-spend"},
	{"apply", "coupon/credit apply race"}, {"transfer", "balance transfer race"},
	{"withdraw", "withdrawal double-spend"}, {"vote", "vote-doubling"},
	{"like", "like-counter race"}, {"gift", "gift-card redeem race"},
	{"invite", "invite-bonus race"}, {"referral", "referral-bonus race"},
	{"promo", "promo-code race"}, {"discount", "discount race"},
	{"claim", "claim/award race"},
}

// Run writes candidate URLs for operator-led validation, without probing them.
func Run(workDir string) error {
	urls, err := iohelp.ReadLines(workDir + "/all_urls.txt")
	if err != nil {
		return fmt.Errorf("read all_urls.txt: %w", err)
	}
	seen := make(map[string]bool)
	var candidates, results []string
	for _, raw := range urls {
		u, parseErr := url.Parse(raw)
		if parseErr != nil || (u.Scheme != "http" && u.Scheme != "https") || seen[raw] {
			continue
		}
		path := strings.ToLower(u.Path)
		for _, keyword := range raceKeywords {
			if strings.Contains(path, keyword.kw) {
				seen[raw] = true
				candidates = append(candidates, fmt.Sprintf("%s\thint=%s", raw, keyword.hint))
				break
			}
		}
	}
	if err := iohelp.WriteLines(workDir+"/race_candidates.txt", candidates); err != nil {
		return err
	}
	if err := iohelp.WriteLines(workDir+"/race_results.txt", results); err != nil {
		return err
	}
	status := "completed"
	if len(urls) == 0 {
		status = "completed_no_input"
	}
	data, err := json.Marshal(map[string]any{
		"status": status, "active_probes": false, "candidate_count": len(candidates),
		"validation": "manual_only", "reason": "non_destructive_mode",
	})
	if err != nil {
		return err
	}
	return os.WriteFile(workDir+"/race_scan_status.json", append(data, '\n'), 0644)
}
