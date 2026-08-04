// Package wafbypass provides a tamper catalog keyed by detected WAF
// vendor. Pipeline stages that wrap payloads (sqlmap, dalfox, nuclei)
// consult this catalog after waf_detect runs and pick the right
// tamper for the scanner command.
//
// The catalog is intentionally simple — most modern bug-bounty
// programs reject tampering-flag misuse in their rules of engagement.
// The catalog is used by stages that already include well-known
// tamper-friendly commands (sqlmap --tamper=..., dalfox --mass
// --bypass-with-...) and the actual flag value comes from the rules
// below.
//
// Two consumers:
//
//  1. Go code (this package) — for finding modules that issue HTTP
//     requests directly (e.g. reflection, paramshape). Returns a
//     "tamper" function that mutates the body string before sending.
//
//  2. Bash stages in pipeline.go — via the BuildShellSnippet function
//     which returns a shell fragment that resolves to the right
//     tamper per detected WAF. Stage commands interpolate this
//     fragment as `${WAF_TAMPER:+...}`.
//
// Why a per-WAF tamper instead of "try every tamper": timing.
// Firing 30 tampered variants per target doubles scan time and
// floods the target. One tamper per detected WAF vendor matches
// well-known fingerprints:
//
//   cloudflare, cloudfront, fastly, akamai → comment-based
//                                            bypasses (HTTP/1.1
//                                            features most)
//   aws                                     → case-mixed headers
//   imperva                                 → chunked transfer
//   f5, barracuda                           → whitespace
//   sucuri                                  → path encoding
//   generic (unknown vendor)                → no tamper; report
//                                            the WAF detection but
//                                            skip the bypass
//
// We don't claim these bypass *work* — the right tamper depends on
// the rule version the WAF is enforcing. The catalog is a starting
// point the hunter iterates from.
package wafbypass

import (
	"bufio"
	"os"
	"strings"
)

// Vendor identifies the WAF vendor the catalog maps from. Strings
// come from wafw00f output. The UnknownVendor zero value means the
// stage should skip the tamper entirely.
type Vendor string

const (
	UnknownVendor    Vendor = ""
	Cloudflare       Vendor = "cloudflare"
	AWS              Vendor = "aws"
	Imperva          Vendor = "imperva"
	Akamai           Vendor = "akamai"
	F5               Vendor = "f5"
	Barracuda        Vendor = "barracuda"
	Sucuri           Vendor = "sucuri"
	Fastly           Vendor = "fastly"
	Cloudfront       Vendor = "cloudfront"
	Generic          Vendor = "generic"
)

// Tamper is one mutation rule. SQLiTamper is the sqlmap `--tamper=`
// script name. DalfoxBypass is the dalfox `--bypass=` arg. HeaderTamper
// is a transformation applied to a header value before sending.
//
// Either field may be empty — vendors differ in which scanners they
// affect.
type Tamper struct {
	SQLiTamper   string
	DalfoxBypass string
	HeaderTamper func(string) string
}

// catalog is the per-vendor tamper map. New vendors = one entry.
var catalog = map[Vendor]Tamper{
	Cloudflare: {
		SQLiTamper:   "between,randomcase,space2comment",
		DalfoxBypass: "wasm",
		HeaderTamper: nil, // CF signature is signed; tamper headers fails
	},
	AWS: {
		SQLiTamper:   "randomcase,space2plus",
		DalfoxBypass: "utf-8",
		HeaderTamper: nil,
	},
	Imperva: {
		SQLiTamper:   "randomcase,between,space2comment",
		DalfoxBypass: "html",
		HeaderTamper: nil,
	},
	Akamai: {
		SQLiTamper:   "randomcase,between,space2comment,versionedkeywords",
		DalfoxBypass: "html",
		HeaderTamper: nil,
	},
	F5: {
		SQLiTamper:   "space2mysqldash,randomcase,between",
		DalfoxBypass: "unicode",
		HeaderTamper: nil,
	},
	Barracuda: {
		SQLiTamper:   "space2mysqldash,randomcase,unionalltounion",
		DalfoxBypass: "html",
		HeaderTamper: nil,
	},
	Sucuri: {
		SQLiTamper:   "between,randomcase,space2comment,modsecurityversioned",
		DalfoxBypass: "html",
		HeaderTamper: nil,
	},
	Fastly: {
		SQLiTamper:   "between,randomcase",
		DalfoxBypass: "utf-8",
		HeaderTamper: nil,
	},
	Cloudfront: {
		SQLiTamper:   "between,randomcase,space2comment",
		DalfoxBypass: "wasm",
		HeaderTamper: nil,
	},
	Generic: {
		// Generic = we detected a WAF but didn't fingerprint the
		// vendor. Best-effort: mild tamper that often slips past.
		SQLiTamper:   "between",
		DalfoxBypass: "html",
		HeaderTamper: nil,
	},
}

// DetectVendor reads the workdir's waf_detections.txt and returns
// the first recognized vendor. Returns UnknownVendor when no WAF is
// detected or the file is missing.
//
// The detection format from wafw00f is one line per host, e.g.:
//
//   https://example.com	[Cloudflare (https://www.cloudflare.com)]
//
// We substring-match against the vendor names. If multiple WAFs
// detected across hosts, the first one wins — same trade-off as the
// per-stage tampers: scan once, report all hosts.
func DetectVendor(workDir string) Vendor {
	f, err := os.Open(workDir + "/waf_detections.txt")
	if err != nil {
		return UnknownVendor
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		for _, v := range []Vendor{Cloudflare, AWS, Imperva, Akamai, F5, Barracuda, Sucuri, Fastly, Cloudfront} {
			if strings.Contains(line, string(v)) {
				return v
			}
		}
		// Generic "is behind a WAF" indicator.
		if strings.Contains(line, "waf") || strings.Contains(line, "firewall") {
			return Generic
		}
	}
	return UnknownVendor
}

// For returns the tamper for the given vendor. UnknownVendor returns
// the zero Tamper (no flags).
func For(v Vendor) Tamper {
	if t, ok := catalog[v]; ok {
		return t
	}
	return Tamper{}
}

// BuildShellSnippet returns a shell fragment that resolves to the
// right tamper flags for the detected WAF. The fragment writes three
// env vars:
//
//   WAF_SQLMAP_TAMPER   — sqlmap --tamper= value (empty if no tamper)
//   WAF_DALFOX_BYPASS   — dalfox --bypass value
//   WAF_HEADER_TAMPER   — reserved for future header-tamper use
//
// Stage commands interpolate these as:
//
//   ${WAF_SQLMAP_TAMPER:+--tamper=$WAF_SQLMAP_TAMPER}
//
// so when no WAF is detected, the flag is omitted cleanly.
func BuildShellSnippet(workDir string) string {
	v := DetectVendor(workDir)
	t := For(v)
	return strings.Join([]string{
		`WAF_VENDOR="` + string(v) + `"`,
		`WAF_SQLMAP_TAMPER="` + t.SQLiTamper + `"`,
		`WAF_DALFOX_BYPASS="` + t.DalfoxBypass + `"`,
		`export WAF_VENDOR WAF_SQLMAP_TAMPER WAF_DALFOX_BYPASS`,
	}, "\n")
}