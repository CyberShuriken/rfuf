package scope

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

var labelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeDomain converts example.com and *.example.com to one stable,
// lowercase root-domain scope. It intentionally accepts DNS names only;
// URLs, paths, IP addresses, and malformed wildcard expressions are rejected.
func NormalizeDomain(input string) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(input))
	if strings.HasPrefix(domain, "*.") {
		domain = strings.TrimPrefix(domain, "*.")
	}
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" || strings.Contains(domain, "/") || strings.Contains(domain, "://") {
		return "", fmt.Errorf("invalid domain scope %q: expected example.com or *.example.com", input)
	}
	if net.ParseIP(domain) != nil {
		return "", fmt.Errorf("IP addresses are not valid wildcard domain scopes: %q", input)
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("domain scope %q must contain at least two labels", input)
	}
	for _, label := range labels {
		if !labelPattern.MatchString(label) {
			return "", fmt.Errorf("invalid DNS label %q in scope %q", label, input)
		}
	}
	return domain, nil
}

// InScopeHost returns true for the exact root domain or a proper subdomain.
// It rejects lookalike suffixes such as example.com.evil.test.
func InScopeHost(host, root string) bool {
	root, err := NormalizeDomain(root)
	if err != nil {
		return false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if parsed, err := url.Parse(host); err == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
	} else {
		host = strings.TrimSuffix(strings.Split(host, "/")[0], ".")
		host = strings.Split(host, ":")[0]
	}
	host = strings.TrimSuffix(host, ".")
	return host == root || strings.HasSuffix(host, "."+root)
}

// FilterLines keeps in-scope hostnames or URLs and returns rejected lines too.
func FilterLines(lines []string, root string) (inScope, outOfScope []string, err error) {
	root, err = NormalizeDomain(root)
	if err != nil {
		return nil, nil, err
	}
	seenIn, seenOut := map[string]bool{}, map[string]bool{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		host := line
		if parsed, parseErr := url.Parse(line); parseErr == nil && parsed.Hostname() != "" {
			host = parsed.Hostname()
		}
		if InScopeHost(host, root) {
			if !seenIn[line] {
				inScope = append(inScope, line)
				seenIn[line] = true
			}
		} else if !seenOut[line] {
			outOfScope = append(outOfScope, line)
			seenOut[line] = true
		}
	}
	sort.Strings(inScope)
	sort.Strings(outOfScope)
	return inScope, outOfScope, nil
}

type Report struct {
	Input       string    `json:"input"`
	RootDomain  string    `json:"root_domain"`
	GeneratedAt time.Time `json:"generated_at"`
	InScope     int       `json:"in_scope"`
	OutOfScope  int       `json:"out_of_scope"`
	InScopeFile string    `json:"in_scope_file"`
	OutFile     string    `json:"out_of_scope_file"`
}

func (r Report) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }
