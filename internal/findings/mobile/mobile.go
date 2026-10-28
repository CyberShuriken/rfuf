// Package mobile performs static analysis of mobile app artifacts (APK/IPA)
// dropped into <workDir>/mobile_artifacts/ and surfaces the backend endpoints
// and secrets baked into the app. Mobile apps routinely ship the full internal
// API surface (hosts, paths, keys) that a web crawl never sees, so this feeds
// the scan corpus with in-scope endpoints the rest of the pipeline can test.
//
// Artifacts are treated as untrusted input: each is read in-memory with
// archive/zip (APK and IPA are both zip containers). Nothing is extracted to
// disk and nothing in the archive is ever executed, so a hostile archive cannot
// plant or run code. Reads are byte- and count-bounded.
//
// Outputs:
//   - mobile_endpoints.txt  in-scope URLs found in the app (fed to the corpus)
//   - mobile_findings.txt    secrets + out-of-app notable URLs (report rows)
package mobile

import (
	"archive/zip"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

var (
	urlRE = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+`)
	// A small, high-signal secret set — enough to flag an obviously embedded
	// credential without turning every base64 blob into a finding.
	secretREs = []struct {
		kind string
		re   *regexp.Regexp
		sev  string
	}{
		{"aws_access_key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "HIGH"},
		{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), "MEDIUM"},
		{"stripe_live", regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{24,}\b`), "CRITICAL"},
		{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_=-]+\.eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_.+/=-]{20,}\b`), "HIGH"},
		{"generic_secret", regexp.MustCompile(`(?i)["'](?:api[_-]?key|client[_-]?secret|access[_-]?token)["']\s*[:=]\s*["']([A-Za-z0-9_/+=.-]{20,})["']`), "MEDIUM"},
	}
)

const (
	maxEntryBytes  = 8 << 20   // per zip entry read cap
	maxTotalBytes  = 200 << 20 // per artifact total read cap
	maxArtifacts   = 10
	maxEndpoints   = 5000
	maxFindings    = 2000
	shortSecretLen = 16
)

// Run is the finder entry point.
func Run(workDir string) error {
	dir := filepath.Join(workDir, "mobile_artifacts")
	entries, err := os.ReadDir(dir)
	if err != nil {
		// No artifacts supplied (no -apk) — clean no-op.
		if werr := iohelp.WriteLines(workDir+"/mobile_endpoints.txt", nil); werr != nil {
			return werr
		}
		return iohelp.WriteLines(workDir+"/mobile_findings.txt", nil)
	}

	endpoints := map[string]bool{}
	findings := map[string]bool{}
	analyzed := 0
	for _, e := range entries {
		if e.IsDir() || analyzed >= maxArtifacts {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".apk" && ext != ".ipa" && ext != ".zip" {
			continue
		}
		analyzed++
		analyzeArtifact(filepath.Join(dir, e.Name()), e.Name(), endpoints, findings)
	}

	return writeOutputs(workDir, endpoints, findings)
}

// analyzeArtifact reads one zip-container app and records endpoints/secrets.
func analyzeArtifact(path, name string, endpoints, findings map[string]bool) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		findings[fmt.Sprintf("INFO\tartifact=%s\tnote=unreadable archive: %v", name, err)] = true
		return
	}
	defer zr.Close()

	var total int64
	for _, f := range zr.File {
		if total >= maxTotalBytes || len(endpoints) >= maxEndpoints {
			break
		}
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(rc, maxEntryBytes))
		rc.Close()
		total += int64(len(data))
		scan(string(data), name, endpoints, findings)
	}
}

// scan extracts URLs and secrets from one decoded entry's bytes.
func scan(body, artifact string, endpoints, findings map[string]bool) {
	for _, m := range urlRE.FindAllString(body, 2000) {
		u, err := url.Parse(strings.TrimRight(m, ".,);'\""))
		if err != nil || u.Host == "" {
			continue
		}
		host := u.Hostname()
		if iohelp.InScope(host) {
			endpoints[u.String()] = true
		} else {
			// Out-of-scope URLs are noted (third-party SDK/backend) but never
			// scanned.
			findings[fmt.Sprintf("INFO\tartifact=%s\ttype=external-url\turl=%s", artifact, u.String())] = true
		}
	}
	for _, sp := range secretREs {
		for _, m := range sp.re.FindAllString(body, 5) {
			short := m
			if len(short) > shortSecretLen+3 {
				short = short[:shortSecretLen] + "..."
			}
			findings[fmt.Sprintf("%s\tartifact=%s\ttype=secret\tkind=%s\tvalue=%s", sp.sev, artifact, sp.kind, short)] = true
		}
	}
}

func writeOutputs(workDir string, endpoints, findings map[string]bool) error {
	eps := keysSorted(endpoints, maxEndpoints)
	if err := iohelp.WriteLines(workDir+"/mobile_endpoints.txt", eps); err != nil {
		return err
	}
	return iohelp.WriteLines(workDir+"/mobile_findings.txt", keysSorted(findings, maxFindings))
}

func keysSorted(m map[string]bool, cap int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > cap {
		out = out[:cap]
	}
	return out
}
