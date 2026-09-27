// Package jsassets collects in-scope JavaScript and manifest assets for later
// static analysis. Every network request is scope-checked before it is sent.
package jsassets

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
	"github.com/CyberShuriken/rfuf/internal/scope"
)

const (
	maxPageBytes  = 2 << 20
	maxAssetBytes = 5 << 20
	maxAssets     = 5000
	maxHosts      = 200
)

var (
	urlLiteralRE = regexp.MustCompile(`(?i)(https?://[^\s"'<>]+|/(?:api|graphql|_next|admin|internal|v[0-9]+)[A-Za-z0-9_./?&=%{}:-]*)`)
	staticRE     = regexp.MustCompile(`(?i)\.(?:js|mjs|map|json|webmanifest)(?:[?#].*)?$`)
	newClient    = func() *http.Client { return &http.Client{Timeout: 15 * time.Second} }
)

type assetMetadata struct {
	URL         string `json:"url"`
	Host        string `json:"host"`
	Kind        string `json:"kind"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	Bytes       int    `json:"bytes"`
	SHA256      string `json:"sha256,omitempty"`
	File        string `json:"file,omitempty"`
}

type assetFailure struct {
	URL    string `json:"url"`
	Host   string `json:"host"`
	Reason string `json:"reason"`
	Status int    `json:"status,omitempty"`
}

// Run reads live hosts, fetches bounded HTML/manifest/JS assets, and writes
// stable asset metadata, failures, and endpoint provenance artifacts.
func Run(workDir string) error {
	parsedScope, err := loadScope(workDir)
	if err != nil {
		return err
	}
	exclusion := strings.TrimSpace(os.Getenv("RFUF_EXCLUDE_URL_REGEX"))
	var exclude *regexp.Regexp
	if exclusion != "" {
		exclude, err = regexp.Compile(exclusion)
		if err != nil {
			return fmt.Errorf("invalid exclusion regex: %w", err)
		}
	}
	hostLines, err := iohelp.ReadLines(filepath.Join(workDir, "alive.txt"))
	if err != nil {
		return fmt.Errorf("read alive.txt: %w", err)
	}
	if len(hostLines) > maxHosts {
		hostLines = hostLines[:maxHosts]
	}
	for _, dir := range []string{"js_bundles"} {
		if err := os.MkdirAll(filepath.Join(workDir, dir), 0755); err != nil {
			return err
		}
	}
	assetsFile, err := os.Create(filepath.Join(workDir, "js_assets.txt"))
	if err != nil {
		return err
	}
	defer assetsFile.Close()
	metaFile, err := os.Create(filepath.Join(workDir, "js_asset_metadata.jsonl"))
	if err != nil {
		return err
	}
	defer metaFile.Close()
	errorFile, err := os.Create(filepath.Join(workDir, "js_asset_errors.jsonl"))
	if err != nil {
		return err
	}
	defer errorFile.Close()
	errorTextFile, err := os.Create(filepath.Join(workDir, "js_asset_errors.txt"))
	if err != nil {
		return err
	}
	defer errorTextFile.Close()
	endpointFile, err := os.Create(filepath.Join(workDir, "js_endpoint_provenance.jsonl"))
	if err != nil {
		return err
	}
	defer endpointFile.Close()
	assetWriter, metaWriter := bufio.NewWriter(assetsFile), bufio.NewWriter(metaFile)
	errorWriter, endpointWriter := bufio.NewWriter(errorFile), bufio.NewWriter(endpointFile)
	errorTextWriter := bufio.NewWriter(errorTextFile)
	client := newClient()
	iohelp.HardenClient(client)
	previousRedirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !parsedScope.IncludesHost(req.URL.Hostname()) || (exclude != nil && exclude.MatchString(req.URL.String())) {
			return fmt.Errorf("redirect_out_of_scope_or_excluded")
		}
		if previousRedirect != nil {
			return previousRedirect(req, via)
		}
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}
	seenAssets, seenEndpoints := map[string]bool{}, map[string]bool{}
	assetCount, failedCount := 0, 0
	for _, raw := range hostLines {
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			continue
		}
		pageURL, parseErr := url.Parse(fields[0])
		if parseErr != nil || (pageURL.Scheme != "http" && pageURL.Scheme != "https") {
			continue
		}
		if !parsedScope.IncludesHost(pageURL.Hostname()) {
			if err := writeFailure(errorWriter, errorTextWriter, &failedCount, fields[0], pageURL.Hostname(), "out_of_scope", 0); err != nil {
				return err
			}
			continue
		}
		if exclude != nil && exclude.MatchString(fields[0]) {
			if err := writeFailure(errorWriter, errorTextWriter, &failedCount, fields[0], pageURL.Hostname(), "excluded", 0); err != nil {
				return err
			}
			continue
		}
		pageBody, pageMeta, pageErr := fetch(client, pageURL.String(), "page", maxPageBytes)
		if pageErr != nil {
			if err := writeFailure(errorWriter, errorTextWriter, &failedCount, pageURL.String(), pageURL.Hostname(), pageErr.Error(), pageMeta.Status); err != nil {
				return err
			}
			continue
		}
		pagePath, err := storeAsset(workDir, pageURL, pageBody, pageMeta.ContentType, "page")
		if err != nil {
			return err
		}
		pageMeta.File = pagePath
		if err := writeJSONLine(metaWriter, pageMeta); err != nil {
			return err
		}
		refs, inline := parseHTML(pageBody)
		for _, v := range inline {
			refs = append(refs, jsonReferences(v)...)
			if err := addEndpoints(endpointWriter, seenEndpoints, pageURL, v, parsedScope, exclude); err != nil {
				return err
			}
		}
		for _, p := range []string{"/manifest.json", "/asset-manifest.json", "/manifest.webmanifest", "/build-manifest.json", "/routes-manifest.json", "/_next/build-manifest.json", "/_next/static/chunks/webpack.js", "/static/js/main.js"} {
			r, _ := pageURL.Parse(p)
			refs = append(refs, r.String())
		}
		queue := make([]string, 0, len(refs))
		for _, ref := range refs {
			if candidate, ok := resolveScoped(pageURL, ref, parsedScope, exclude); ok {
				if isAsset(candidate) {
					queue = append(queue, candidate)
				}
			} else if candidate != "" {
				if err := writeFailure(errorWriter, errorTextWriter, &failedCount, candidate, pageURL.Hostname(), "out_of_scope_or_excluded", 0); err != nil {
					return err
				}
			}
		}
		for len(queue) > 0 && assetCount < maxAssets {
			assetURL := queue[0]
			queue = queue[1:]
			if seenAssets[assetURL] {
				continue
			}
			seenAssets[assetURL] = true
			assetParsed, _ := url.Parse(assetURL)
			body, meta, fetchErr := fetch(client, assetURL, assetKind(assetParsed), maxAssetBytes)
			if fetchErr != nil {
				if err := writeFailure(errorWriter, errorTextWriter, &failedCount, assetURL, assetParsed.Hostname(), fetchErr.Error(), meta.Status); err != nil {
					return err
				}
				continue
			}
			name, err := storeAsset(workDir, assetParsed, body, meta.ContentType, meta.Kind)
			if err != nil {
				return err
			}
			meta.File = name
			if err := writeJSONLine(metaWriter, meta); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(assetWriter, assetURL); err != nil {
				return err
			}
			assetCount++
			content := string(body)
			if strings.Contains(strings.ToLower(meta.ContentType), "json") || strings.HasSuffix(strings.ToLower(assetParsed.Path), ".json") || strings.HasSuffix(strings.ToLower(assetParsed.Path), ".webmanifest") {
				for _, ref := range jsonReferences(content) {
					if next, ok := resolveScoped(pageURL, ref, parsedScope, exclude); ok {
						if isAsset(next) && !seenAssets[next] {
							queue = append(queue, next)
						}
					} else if next != "" {
						if err := writeFailure(errorWriter, errorTextWriter, &failedCount, next, assetParsed.Hostname(), "out_of_scope_or_excluded", 0); err != nil {
							return err
						}
					}
				}
			}
			if err := addEndpoints(endpointWriter, seenEndpoints, pageURL, content, parsedScope, exclude); err != nil {
				return err
			}
		}
	}
	for _, w := range []*bufio.Writer{assetWriter, metaWriter, errorWriter, errorTextWriter, endpointWriter} {
		if err := w.Flush(); err != nil {
			return err
		}
	}
	assets, err := iohelp.ReadLines(filepath.Join(workDir, "js_assets.txt"))
	if err != nil {
		return err
	}
	sort.Strings(assets)
	if err := iohelp.WriteLines(filepath.Join(workDir, "js_assets.txt"), assets); err != nil {
		return err
	}
	var endpointLines []string
	if err := readEndpointLines(filepath.Join(workDir, "js_endpoint_provenance.jsonl"), &endpointLines); err != nil {
		return err
	}
	if err := iohelp.WriteLines(filepath.Join(workDir, "js_endpoints.txt"), unique(endpointLines)); err != nil {
		return err
	}
	status := map[string]any{"status": "completed", "hosts": len(hostLines), "assets": assetCount, "failures": failedCount}
	if len(hostLines) == 0 {
		status["status"] = "completed_no_input"
	}
	data, err := json.Marshal(status)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(workDir, "jsmap_status.txt"), append(data, '\n'), 0644)
}

func loadScope(workDir string) (scope.Scope, error) {
	if input := strings.TrimSpace(os.Getenv("RFUF_SCOPE_INPUT")); input != "" {
		return scope.Parse(input)
	}
	data, err := os.ReadFile(filepath.Join(workDir, "scope.json"))
	if err != nil {
		return scope.Scope{}, fmt.Errorf("read scope.json: %w", err)
	}
	var parsed scope.Scope
	if err := json.Unmarshal(data, &parsed); err != nil {
		return scope.Scope{}, err
	}
	if parsed.RootDomain == "" {
		return scope.Parse(parsed.Input)
	}
	return parsed, nil
}

func fetch(client *http.Client, rawURL, kind string, limit int64) ([]byte, assetMetadata, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, assetMetadata{}, err
	}
	meta := assetMetadata{URL: rawURL, Host: parsed.Hostname(), Kind: kind}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := iohelp.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, meta, err
	}
	req.Header.Set("User-Agent", "rfuf-jsassets/1.0")
	iohelp.ApplyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil, meta, err
	}
	defer resp.Body.Close()
	meta.Status, meta.ContentType = resp.StatusCode, resp.Header.Get("Content-Type")
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, meta, err
	}
	if int64(len(body)) > limit {
		return nil, meta, fmt.Errorf("response_too_large")
	}
	meta.Bytes = len(body)
	digest := sha256.Sum256(body)
	meta.SHA256 = hex.EncodeToString(digest[:])
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, meta, fmt.Errorf("http_status_%d", resp.StatusCode)
	}
	return body, meta, nil
}

func storeAsset(workDir string, parsed *url.URL, body []byte, contentType, kind string) (string, error) {
	canonical := parsed.String()
	hash := md5.Sum([]byte(canonical))
	ext := filepath.Ext(parsed.Path)
	if ext == "" {
		if strings.Contains(strings.ToLower(contentType), "json") {
			ext = ".json"
		} else if kind == "page" {
			ext = ".html"
		} else {
			ext = ".js"
		}
	}
	file := filepath.Join("js_bundles", safe(parsed.Hostname())+"_"+hex.EncodeToString(hash[:])+ext)
	if err := os.WriteFile(filepath.Join(workDir, file), body, 0644); err != nil {
		return "", err
	}
	return file, nil
}

func parseHTML(body []byte) ([]string, []string) {
	var refs, inline []string
	s := string(body)
	lower := strings.ToLower(s)
	for pos := 0; pos < len(s); {
		rel := strings.IndexByte(s[pos:], '<')
		if rel < 0 {
			break
		}
		start := pos + rel
		if strings.HasPrefix(s[start:], "<!--") {
			end := strings.Index(s[start+4:], "-->")
			if end < 0 {
				break
			}
			pos = start + 4 + end + 3
			continue
		}
		end := tagEnd(s, start+1)
		if end < 0 {
			break
		}
		tag, attrs := parseTag(s[start+1 : end])
		pos = end + 1
		if tag == "script" && !strings.HasPrefix(s[start+1:], "/") {
			if src := attrs["src"]; src != "" {
				refs = append(refs, src)
			}
			closeAt := strings.Index(lower[pos:], "</script")
			if closeAt >= 0 {
				content := s[pos : pos+closeAt]
				if strings.Contains(strings.ToLower(attrs["type"]), "json") || strings.Contains(content, "__NEXT_DATA__") {
					inline = append(inline, content)
				}
				pos += closeAt
			}
		} else if tag == "link" {
			rel := strings.ToLower(attrs["rel"])
			if attrs["href"] != "" && (strings.Contains(rel, "preload") || strings.Contains(rel, "modulepreload") || strings.Contains(rel, "manifest") || staticRE.MatchString(attrs["href"])) {
				refs = append(refs, attrs["href"])
			}
		}
	}
	return refs, inline
}

func tagEnd(s string, start int) int {
	quote := byte(0)
	for i := start; i < len(s); i++ {
		if quote != 0 {
			if s[i] == quote {
				quote = 0
			}
			continue
		}
		if s[i] == '\'' || s[i] == '"' {
			quote = s[i]
		} else if s[i] == '>' {
			return i
		}
	}
	return -1
}

func parseTag(s string) (string, map[string]string) {
	i := 0
	for i < len(s) && (s[i] == '/' || s[i] == ' ' || s[i] == '\n' || s[i] == '\t') {
		i++
	}
	start := i
	for i < len(s) && isName(s[i]) {
		i++
	}
	tag := strings.ToLower(s[start:i])
	attrs := map[string]string{}
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\n' || s[i] == '\t' || s[i] == '/') {
			i++
		}
		start = i
		for i < len(s) && isName(s[i]) {
			i++
		}
		if start == i {
			i++
			continue
		}
		name := strings.ToLower(s[start:i])
		for i < len(s) && (s[i] == ' ' || s[i] == '\n' || s[i] == '\t') {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			continue
		}
		i++
		for i < len(s) && (s[i] == ' ' || s[i] == '\n' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		q := s[i]
		var value string
		if q == '\'' || q == '"' {
			i++
			start = i
			for i < len(s) && s[i] != q {
				i++
			}
			value = s[start:i]
			if i < len(s) {
				i++
			}
		} else {
			start = i
			for i < len(s) && s[i] != ' ' && s[i] != '\n' && s[i] != '\t' {
				i++
			}
			value = s[start:i]
		}
		attrs[name] = value
	}
	return tag, attrs
}

func isName(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_'
}

func jsonReferences(data string) []string {
	var value any
	if json.Unmarshal([]byte(data), &value) != nil {
		return nil
	}
	var refs []string
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			if strings.HasPrefix(x, "/") || strings.HasPrefix(x, "http://") || strings.HasPrefix(x, "https://") || staticRE.MatchString(x) {
				refs = append(refs, x)
			}
		case []any:
			for _, item := range x {
				walk(item)
			}
		case map[string]any:
			for _, item := range x {
				walk(item)
			}
		}
	}
	walk(value)
	return refs
}

func resolveScoped(base *url.URL, ref string, scanScope scope.Scope, exclude *regexp.Regexp) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return "", false
	}
	resolved := base.ResolveReference(parsed)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return "", false
	}
	if !scanScope.IncludesHost(resolved.Hostname()) {
		return resolved.String(), false
	}
	if exclude != nil && exclude.MatchString(resolved.String()) {
		return resolved.String(), false
	}
	return resolved.String(), true
}

func isAsset(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return staticRE.MatchString(parsed.Path) || strings.Contains(parsed.Path, "/_next/static/") || strings.Contains(parsed.Path, "manifest")
}
func assetKind(parsed *url.URL) string {
	if strings.Contains(strings.ToLower(parsed.Path), "manifest") || strings.HasSuffix(strings.ToLower(parsed.Path), ".json") || strings.HasSuffix(strings.ToLower(parsed.Path), ".webmanifest") {
		return "manifest"
	}
	return "script"
}
func safe(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
func writeJSONLine(w io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}
func writeFailure(w, textWriter io.Writer, count *int, raw, host, reason string, status int) error {
	*count++
	if err := writeJSONLine(w, assetFailure{URL: raw, Host: host, Reason: reason, Status: status}); err != nil {
		return err
	}
	_, err := fmt.Fprintf(textWriter, "%s %s\n", reason, raw)
	return err
}
func addEndpoints(w io.Writer, seen map[string]bool, base *url.URL, body string, scanScope scope.Scope, exclude *regexp.Regexp) error {
	for _, candidate := range urlLiteralRE.FindAllString(body, 1000) {
		if resolved, ok := resolveScoped(base, candidate, scanScope, exclude); ok && !seen[resolved] {
			seen[resolved] = true
			if err := writeJSONLine(w, map[string]string{"url": resolved, "source": base.String()}); err != nil {
				return err
			}
		}
	}
	return nil
}
func readEndpointLines(path string, out *[]string) error {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		var rec struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(s.Bytes(), &rec) == nil && rec.URL != "" {
			*out = append(*out, rec.URL)
		}
	}
	return s.Err()
}
func unique(lines []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if !seen[line] {
			seen[line] = true
			out = append(out, line)
		}
	}
	sort.Strings(out)
	return out
}

// fixtureDialer is used by package tests to route fixture domains to loopback.
func fixtureDialer(address string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
}
