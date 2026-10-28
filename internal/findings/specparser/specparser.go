package specparser

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

// Run parses OpenAPI/Swagger specs and sitemaps found in workDir/api_specs and
// writes testable endpoints to workDir/openapi_paths.txt.
//
// For every OpenAPI/Swagger path it emits two forms so both scanner lanes are
// fed: the bare path (for param-agnostic nuclei/path testing) and, when the
// operation declares query parameters, a synthesized `path?name=FUZZ&...` URL
// (so the param-hungry DAST generators — sqlmap/dalfox/ghauri — finally have
// real query targets instead of the empty set a SPA/REST target used to yield).
//
// The base host is read from the `<specfile>.src` sidecar written by the
// api_discovery stage (the real fetch URL); api_discovery collapses dots and
// slashes to '_' in the filename, so the filename alone cannot reconstruct a
// host. A lossy filename fallback is kept for specs captured before sidecars.
func Run(workDir string) error {
	specsDir := filepath.Join(workDir, "api_specs")
	outPath := filepath.Join(workDir, "openapi_paths.txt")

	files, err := os.ReadDir(specsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return iohelp.WriteLines(outPath, nil)
		}
		return fmt.Errorf("failed to read specs dir: %w", err)
	}

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer out.Close()
	writer := bufio.NewWriter(out)
	defer writer.Flush()

	seen := map[string]bool{}
	emit := func(u string) {
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		writer.WriteString(u + "\n")
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		ext := filepath.Ext(file.Name())
		if ext != ".json" && ext != ".yaml" && ext != ".yml" && ext != ".xml" {
			continue // skip .src sidecars and anything else
		}
		specPath := filepath.Join(specsDir, file.Name())
		base := baseURLFor(specPath, file.Name(), ext)

		if ext == ".xml" {
			for _, u := range sitemapURLs(specPath) {
				emit(u)
			}
			continue
		}

		// YAML specs are not parsed yet (the module is dependency-free and the
		// stdlib has no YAML decoder); api_discovery fetches JSON specs.
		if ext != ".json" {
			continue
		}
		for _, u := range openAPIURLs(specPath, base) {
			emit(u)
		}
	}
	return nil
}

// baseURLFor returns scheme://host for a spec, preferring the real fetch URL
// recorded in the `.src` sidecar and falling back to the lossy filename scheme.
func baseURLFor(specPath, name, ext string) string {
	if data, err := os.ReadFile(specPath + ".src"); err == nil {
		if u, perr := url.Parse(strings.TrimSpace(string(data))); perr == nil && u.Host != "" {
			return u.Scheme + "://" + u.Host
		}
	}
	// Fallback: strip ext + spec suffixes, turn '_' back into '.'/'/'. Lossy,
	// but better than nothing for specs captured before sidecars existed.
	h := strings.TrimSuffix(name, ext)
	h = strings.TrimSuffix(h, ".openapi")
	h = strings.TrimSuffix(h, ".swagger")
	h = strings.ReplaceAll(h, "_", "/")
	if !strings.HasPrefix(h, "http") {
		h = "https://" + h
	}
	return strings.TrimSuffix(h, "/")
}

// openAPIURLs decodes an OpenAPI/Swagger JSON doc and returns path + synthesized
// param URLs. Returns nil for anything without a usable `paths` object (which
// drops 404 HTML bodies, robots.txt, and other non-spec responses).
func openAPIURLs(specPath, base string) []string {
	data, err := os.ReadFile(specPath)
	if err != nil {
		return nil
	}
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || len(doc.Paths) == 0 {
		return nil
	}

	var urls []string
	for rawPath, item := range doc.Paths {
		if !strings.HasPrefix(rawPath, "/") {
			continue
		}
		p := substitutePathParams(rawPath)
		urls = append(urls, base+p)

		// Collect query-param names from path-level and per-method parameters.
		names := map[string]bool{}
		for key, raw := range item {
			// key is either "parameters" (path-level) or an HTTP method object.
			collectQueryParams(key, raw, names)
		}
		if len(names) > 0 {
			var pairs []string
			for n := range names {
				pairs = append(pairs, n+"=FUZZ")
			}
			urls = append(urls, base+p+"?"+strings.Join(pairs, "&"))
		}
	}
	return urls
}

// collectQueryParams extracts `in: query` parameter names from either a
// path-level `parameters` array or an operation object's `parameters` array.
func collectQueryParams(key string, raw json.RawMessage, out map[string]bool) {
	type param struct {
		Name string `json:"name"`
		In   string `json:"in"`
	}
	add := func(ps []param) {
		for _, p := range ps {
			if p.In == "query" && p.Name != "" {
				out[p.Name] = true
			}
		}
	}
	if key == "parameters" {
		var ps []param
		if json.Unmarshal(raw, &ps) == nil {
			add(ps)
		}
		return
	}
	// Otherwise treat key as an operation (get/post/...); pull its parameters.
	var op struct {
		Parameters []param `json:"parameters"`
	}
	if json.Unmarshal(raw, &op) == nil {
		add(op.Parameters)
	}
}

// substitutePathParams replaces OpenAPI `{id}`-style template segments with a
// concrete placeholder so the emitted URL is resolvable and fuzzable.
func substitutePathParams(p string) string {
	for strings.Contains(p, "{") {
		open := strings.Index(p, "{")
		close := strings.Index(p[open:], "}")
		if close < 0 {
			break
		}
		p = p[:open] + "1" + p[open+close+1:]
	}
	return p
}

// sitemapURLs extracts <loc> URLs from an XML sitemap.
func sitemapURLs(specPath string) []string {
	data, err := os.ReadFile(specPath)
	if err != nil {
		return nil
	}
	var urls []string
	s := string(data)
	for {
		i := strings.Index(s, "<loc>")
		if i < 0 {
			break
		}
		s = s[i+len("<loc>"):]
		j := strings.Index(s, "</loc>")
		if j < 0 {
			break
		}
		u := strings.TrimSpace(s[:j])
		if u != "" {
			urls = append(urls, u)
		}
		s = s[j+len("</loc>"):]
	}
	return urls
}
