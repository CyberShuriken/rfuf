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

type Mode string

const (
	ExactMode    Mode = "exact"
	WildcardMode Mode = "wildcard"
)

type Scope struct {
	Input      string `json:"input"`
	RootDomain string `json:"root_domain"`
	Mode       Mode   `json:"mode"`
}

// Parse preserves whether the operator explicitly supplied a wildcard.
// Bare example.com means the exact host only; *.example.com means the root
// plus proper subdomains. URLs, IP addresses, and malformed wildcard input
// are rejected.
func Parse(input string) (Scope, error) {
	original := strings.TrimSpace(input)
	normalized := strings.ToLower(original)
	wildcard := strings.HasPrefix(normalized, "*.")
	if wildcard {
		normalized = strings.TrimPrefix(normalized, "*.")
	}
	if strings.Contains(normalized, "*") {
		return Scope{}, fmt.Errorf("invalid domain scope %q: wildcard must be written as *.example.com", input)
	}
	root, err := normalizeRoot(normalized, input)
	if err != nil {
		return Scope{}, err
	}
	mode := ExactMode
	if wildcard {
		mode = WildcardMode
	}
	return Scope{Input: original, RootDomain: root, Mode: mode}, nil
}

// NormalizeDomain returns the validated root domain for compatibility with
// callers that only need the stable output-directory name.
func NormalizeDomain(input string) (string, error) {
	parsed, err := Parse(input)
	if err != nil {
		return "", err
	}
	return parsed.RootDomain, nil
}

func normalizeRoot(input, original string) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(input))
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" || strings.Contains(domain, "/") || strings.Contains(domain, "://") {
		return "", fmt.Errorf("invalid domain scope %q: expected example.com or *.example.com", original)
	}
	if net.ParseIP(domain) != nil {
		return "", fmt.Errorf("IP addresses are not valid domain scopes: %q", original)
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("domain scope %q must contain at least two labels", original)
	}
	for _, label := range labels {
		if !labelPattern.MatchString(label) {
			return "", fmt.Errorf("invalid DNS label %q in scope %q", label, original)
		}
	}
	return domain, nil
}

func (s Scope) IncludesHost(host string) bool {
	host = normalizeHost(host)
	if host == "" || host == "<nil>" {
		return false
	}
	if s.Mode == ExactMode {
		return host == s.RootDomain
	}
	return host == s.RootDomain || strings.HasSuffix(host, "."+s.RootDomain)
}

func normalizeHost(input string) string {
	host := strings.ToLower(strings.TrimSpace(input))
	if parsed, err := url.Parse(host); err == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
	} else {
		host = strings.TrimSuffix(strings.Split(host, "/")[0], ".")
		host = strings.Split(host, ":")[0]
	}
	return strings.TrimSuffix(host, ".")
}

// InScopeHost parses root as a scope expression. Therefore a bare root is
// exact-only and an explicit *.root expression includes subdomains.
func InScopeHost(host, root string) bool {
	parsed, err := Parse(root)
	return err == nil && parsed.IncludesHost(host)
}

// FilterLines keeps lines allowed by the exact or wildcard scope expression.
func FilterLines(lines []string, scopeInput string) (inScope, outOfScope []string, err error) {
	parsed, err := Parse(scopeInput)
	if err != nil {
		return nil, nil, err
	}
	seenIn, seenOut := map[string]bool{}, map[string]bool{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if parsed.IncludesHost(line) {
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
	Mode        Mode      `json:"mode"`
	GeneratedAt time.Time `json:"generated_at"`
	InScope     int       `json:"in_scope"`
	OutOfScope  int       `json:"out_of_scope"`
	InScopeFile string    `json:"in_scope_file"`
	OutFile     string    `json:"out_of_scope_file"`
}

func (r Report) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }
