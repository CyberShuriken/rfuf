// Package notify posts a run digest to a webhook so a hunter learns about new
// attack surface or findings without opening the output directory. It speaks
// Slack incoming-webhook, Discord webhook, and a generic JSON format, and by
// default stays quiet unless the run-over-run diff surfaced something new.
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/CyberShuriken/rfuf/internal/digest"
)

// Config controls where and how notifications are sent.
type Config struct {
	// Webhook is the destination URL. Empty disables notifications.
	Webhook string
	// Type is the payload format: "auto" (default), "slack", "discord", or
	// "generic". "auto" infers the format from the webhook host.
	Type string
	// On is "change" (default: only notify when the diff found new
	// subdomains or JS) or "always" (notify on every completed run).
	On string
}

// maxList bounds how many new entries are listed in a message body.
const maxList = 15

var httpClient = &http.Client{Timeout: 15 * time.Second}

// Maybe sends a notification subject to cfg.On. It returns nil (and prints a
// short reason) when there is nothing to report, so callers can invoke it
// unconditionally at the end of a run.
func Maybe(cfg Config, d digest.Digest) error {
	if strings.TrimSpace(cfg.Webhook) == "" {
		return nil
	}
	changed := len(d.NewSubdomains) > 0 || len(d.NewJSAssets) > 0
	on := strings.ToLower(strings.TrimSpace(cfg.On))
	if on == "" {
		on = "change"
	}
	if on == "change" && !changed {
		fmt.Println("[*] notify: no new subdomains or JS since last run; skipping (use -notify-on always to force)")
		return nil
	}
	return Send(cfg, d)
}

// Send unconditionally posts the digest to the configured webhook.
func Send(cfg Config, d digest.Digest) error {
	payload, err := buildPayload(cfg, d)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, cfg.Webhook, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	fmt.Printf("[*] notify: sent run digest to %s webhook\n", detectType(cfg))
	return nil
}

func buildPayload(cfg Config, d digest.Digest) ([]byte, error) {
	switch detectType(cfg) {
	case "slack":
		return json.Marshal(map[string]string{"text": renderText(d)})
	case "discord":
		return json.Marshal(map[string]string{"content": renderText(d)})
	default: // generic: post the full structured digest
		return json.MarshalIndent(d, "", "  ")
	}
}

// detectType resolves the payload format, inferring from the webhook host when
// Type is empty or "auto".
func detectType(cfg Config) string {
	t := strings.ToLower(strings.TrimSpace(cfg.Type))
	if t != "" && t != "auto" {
		return t
	}
	host := strings.ToLower(cfg.Webhook)
	switch {
	case strings.Contains(host, "hooks.slack.com"):
		return "slack"
	case strings.Contains(host, "discord.com/api/webhooks"), strings.Contains(host, "discordapp.com/api/webhooks"):
		return "discord"
	default:
		return "generic"
	}
}

// renderText produces a compact human-readable summary for chat webhooks.
func renderText(d digest.Digest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "RFUF %s — %d new subdomain(s), %d new JS asset(s), %d finding(s)\n",
		d.Domain, len(d.NewSubdomains), len(d.NewJSAssets), d.TotalFindings)

	if len(d.NewSubdomains) > 0 {
		b.WriteString("\nNew subdomains:\n")
		writeList(&b, d.NewSubdomains)
	}
	if len(d.NewJSAssets) > 0 {
		b.WriteString("\nNew JS assets:\n")
		writeList(&b, d.NewJSAssets)
	}
	if len(d.Findings) > 0 {
		b.WriteString("\nFindings by class:\n")
		for _, c := range d.Findings {
			fmt.Fprintf(&b, "- [%s] %s: %d\n", c.Severity, c.Name, c.Count)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func writeList(b *strings.Builder, items []string) {
	n := len(items)
	if n > maxList {
		n = maxList
	}
	for _, item := range items[:n] {
		fmt.Fprintf(b, "- %s\n", item)
	}
	if len(items) > maxList {
		fmt.Fprintf(b, "- … and %d more\n", len(items)-maxList)
	}
}
