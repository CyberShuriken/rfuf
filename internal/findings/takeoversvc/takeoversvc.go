// Package takeoversvc implements F9: per-service subdomain takeover
// fingerprints.
//
// `subzy` + `nuclei -t takeovers` cover the well-known 3rd-party
// services from the original can-i-take-over-xyz list. This module
// adds the services that have appeared in the last 24 months:
//
//   - AWS CloudFront (S3-alias distribution that's been deleted)
//   - AWS Amplify (custom-domain pointer to a deleted app)
//   - Vercel (cname.vercel-dns.com) — fingerprinted by the specific
//     "DEPLOYMENT_NOT_FOUND" 404 page
//   - Netlify (custom-domain pointer to a deleted site) —
//     fingerprinted by "Not Found - Request ID: ..."
//   - Fly.io (Edge apps via fly-global-lb) — fingerprinted by the
//     empty 404 + Fly-Request-Id header
//   - Azure Static Web Apps (404 with "The content you are looking
//     for does not exist or has been moved")
//   - Cognito Forms (subdomain pointing to a deleted form)
//   - Intercom (custom host pointing to a deleted workspace)
//
// Output: takeover_v2_findings.txt with one row per fingerprint
// match. The row format is `host<TAB>service<TAB>evidence<TAB>severity`.
//
// We only GET the host (no DNS resolution tricks). For each alive
// host, we match the response body and headers against the per-
// service fingerprints. A hit means "this host resolves to {service}
// and that service's resource appears to be deleted."
package takeoversvc

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

// service is a 3rd-party service fingerprint: name, body/header
// signals, and a description the hunter reads.
type service struct {
	name  string
	body  []string
	hdrs  map[string]string
	desc  string
	sev   string
}

// fingerprintPack is the list of services the module knows about.
// Adding a new service is one struct literal — the matcher is
// generic. Body strings are substring-matched; headers are
// case-insensitive.
var fingerprintPack = []service{
	{
		name: "vercel",
		body: []string{
			"DEPLOYMENT_NOT_FOUND",
			"The deployment could not be found",
			"DEPLOYMENT_ID_NOT_FOUND",
		},
		desc: "Vercel deployment deleted; cname.vercel-dns.com points to a non-existent app",
		sev:  "HIGH",
	},
	{
		name: "netlify",
		body: []string{
			"Not Found - Request ID:",
		},
		hdrs: map[string]string{
			"Server": "Netlify",
		},
		desc: "Netlify site deleted; custom domain still points to it",
		sev:  "HIGH",
	},
	{
		name: "fly",
		body: []string{},
		hdrs: map[string]string{
			"Fly-Request-Id": "",
		},
		desc: "Fly.io edge app deleted; fly-global-lb points to nothing",
		sev:  "HIGH",
	},
	{
		name: "azure-swa",
		body: []string{
			"The content you are looking for does not exist or has been moved",
		},
		desc: "Azure Static Web Apps app deleted",
		sev:  "HIGH",
	},
	{
		name: "aws-amplify",
		body: []string{
			"404 Not Found",
		},
		hdrs: map[string]string{
			"Server": "AmazonS3",
		},
		desc: "AWS Amplify app deleted; bucket returned empty",
		sev:  "MEDIUM",
	},
	{
		name: "cloudfront-deleted",
		body: []string{
			"Bad Request: ERROR: The request could not be satisfied",
			"Request could not be satisfied",
		},
		desc: "CloudFront distribution with a deleted S3 origin",
		sev:  "HIGH",
	},
	{
		name: "intercom",
		body: []string{
			"This page didn't load",
		},
		hdrs: map[string]string{
			"X-Intercom-Version": "",
		},
		desc: "Intercom workspace deleted; custom host still points",
		sev:  "MEDIUM",
	},
	{
		name: "cognito-forms",
		body: []string{
			"Form not found",
		},
		desc: "Cognito Forms form deleted; subdomain still resolves",
		sev:  "MEDIUM",
	},
}

// Run is the entry point. workDir is the rfuf work dir.
func Run(workDir string) error {
	hosts, err := iohelp.ReadLines(workDir + "/live_subs.txt")
	if err != nil {
		return fmt.Errorf("read live_subs.txt: %w", err)
	}
	if len(hosts) == 0 {
		// Fallback: use alive.txt. live_subs is the broader set (DNS-
		// resolving), alive.txt is the http-responding subset. For
		// takeover checks, live_subs is preferred but alive.txt still
		// works.
		hosts, _ = iohelp.ReadLines(workDir + "/alive.txt")
	}
	if len(hosts) == 0 {
		return iohelp.WriteLines(workDir+"/takeover_v2_findings.txt", nil)
	}
	// Cap to 300 — takeover fingerprinting is one GET per host, but
	// we want to cover the full DNS-resolving set.
	const cap = 300
	if len(hosts) > cap {
		hosts = hosts[:cap]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	rows := probeAll(ctx, hosts)
	return iohelp.WriteLines(workDir+"/takeover_v2_findings.txt", rows)
}

func probeAll(ctx context.Context, hosts []string) []string {
	sem := make(chan struct{}, 25)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var rows []string

	tr := &http.Transport{MaxIdleConns: 100, MaxIdleConnsPerHost: 5}
	client := &http.Client{
		Transport: tr,
		Timeout:   6 * time.Second,
	}

	for _, h := range hosts {
		h := h
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			r := probeHost(ctx, client, h)
			if len(r) > 0 {
				mu.Lock()
				rows = append(rows, r...)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return rows
}

func probeHost(ctx context.Context, client *http.Client, host string) []string {
	req, err := http.NewRequestWithContext(ctx, "GET", host, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "rfuf-takeoversvc/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	resp.Body.Close()

	bodyStr := string(body)
	var rows []string
	for _, svc := range fingerprintPack {
		// Header check: every required header must be present (and
		// when a value is given, must match).
		allHdrMatch := true
		for k, want := range svc.hdrs {
			got := resp.Header.Get(k)
			if got == "" {
				allHdrMatch = false
				break
			}
			if want != "" && !strings.EqualFold(got, want) {
				allHdrMatch = false
				break
			}
		}
		if !allHdrMatch {
			continue
		}
		// Body check: at least one body marker must be present.
		anyBodyMatch := false
		for _, b := range svc.body {
			if strings.Contains(bodyStr, b) {
				anyBodyMatch = true
				break
			}
		}
		if !anyBodyMatch {
			continue
		}
		rows = append(rows, fmt.Sprintf("%s\t%s\t%s\tseverity=%s\t%s",
			host, svc.name, truncate(evidence(resp, svc), 120), svc.sev, svc.desc))
	}
	return rows
}

func evidence(resp *http.Response, svc service) string {
	// Pick a short, useful evidence string: matched body marker or
	// matched header value.
	for k := range svc.hdrs {
		if v := resp.Header.Get(k); v != "" {
			return fmt.Sprintf("%s: %s", k, v)
		}
	}
	return svc.body[0]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
