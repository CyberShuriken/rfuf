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

// Candidate retains the source(s) that contributed a normalized target.
type Candidate struct {
	Value   string   `json:"value"`
	Sources []string `json:"sources"`
}

// StreamCounts records how target candidates were accepted or rejected.
type StreamCounts struct {
	Input      int       `json:"input_count"`
	InScope    int       `json:"in_scope_count"`
	Excluded   int       `json:"excluded_count"`
	OutOfScope int       `json:"out_of_scope_count"`
	Duplicate  int       `json:"duplicate_count"`
	Capped     int       `json:"capped_count"`
	Invalid    int       `json:"invalid_count"`
	Final      int       `json:"final_count"`
	Reason     string    `json:"zero_reason,omitempty"`
	Generated  time.Time `json:"generated_at"`
}

// CanonicalizeStream normalizes, scopes, excludes, deduplicates, and caps a
// line-oriented source before it can become input to an active scanner.
func CanonicalizeStream(lines []string, source string, scanScope Scope, exclusion string, maxTargets int) ([]Candidate, StreamCounts, error) {
	counts := StreamCounts{Generated: time.Now().UTC()}
	var exclude *regexp.Regexp
	var err error
	if exclusion != "" {
		exclude, err = regexp.Compile(exclusion)
		if err != nil {
			return nil, counts, fmt.Errorf("invalid exclusion expression")
		}
	}
	byValue := make(map[string]map[string]bool)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		counts.Input++
		fields := strings.Fields(line)
		if len(fields) > 1 {
			if len(fields) != 2 || len(fields[1]) != 5 || fields[1][0] != '[' || fields[1][4] != ']' {
				counts.Invalid++
				continue
			}
			line = fields[0]
		}
		value, host, valid := normalizeCandidate(line)
		if !valid {
			counts.Invalid++
			continue
		}
		if !scanScope.IncludesHost(host) {
			counts.OutOfScope++
			continue
		}
		counts.InScope++
		if exclude != nil && exclude.MatchString(value) {
			counts.Excluded++
			continue
		}
		if _, exists := byValue[value]; exists {
			counts.Duplicate++
		}
		if byValue[value] == nil {
			byValue[value] = make(map[string]bool)
		}
		byValue[value][source] = true
	}
	values := make([]string, 0, len(byValue))
	for value := range byValue {
		values = append(values, value)
	}
	sort.Strings(values)
	if maxTargets > 0 && len(values) > maxTargets {
		counts.Capped = len(values) - maxTargets
		values = values[:maxTargets]
	}
	result := make([]Candidate, 0, len(values))
	for _, value := range values {
		sources := make([]string, 0, len(byValue[value]))
		for name := range byValue[value] {
			sources = append(sources, name)
		}
		sort.Strings(sources)
		result = append(result, Candidate{Value: value, Sources: sources})
	}
	counts.Final = len(result)
	if counts.Final == 0 {
		switch {
		case counts.Input == 0:
			counts.Reason = "no_input"
		case counts.OutOfScope > 0 && counts.InScope == 0:
			counts.Reason = "no_in_scope_targets"
		case counts.Excluded > 0 && counts.Excluded == counts.InScope:
			counts.Reason = "all_targets_excluded"
		case counts.Capped > 0:
			counts.Reason = "target_limit"
		default:
			counts.Reason = "no_valid_targets"
		}
	}
	return result, counts, nil
}

func normalizeCandidate(raw string) (value, host string, valid bool) {
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.User != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return "", "", false
		}
		host = strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		port := u.Port()
		if net.ParseIP(host) == nil {
			for _, label := range strings.Split(host, ".") {
				if !labelPattern.MatchString(label) {
					return "", "", false
				}
			}
		}
		u.Scheme = strings.ToLower(u.Scheme)
		if port != "" && !((u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443")) {
			u.Host = net.JoinHostPort(host, port)
		} else if strings.Contains(host, ":") {
			u.Host = "[" + host + "]"
		} else {
			u.Host = host
		}
		u.Fragment = ""
		if u.Path == "" {
			u.Path = "/"
		}
		return u.String(), host, true
	}
	host = strings.ToLower(strings.TrimSuffix(raw, "."))
	if strings.ContainsAny(host, "/?#@ \t\r\n") {
		return "", "", false
	}
	if net.ParseIP(host) == nil {
		for _, label := range strings.Split(host, ".") {
			if !labelPattern.MatchString(label) {
				return "", "", false
			}
		}
	}
	return host, host, true
}

func (c StreamCounts) JSON() ([]byte, error) { return json.MarshalIndent(c, "", "  ") }
