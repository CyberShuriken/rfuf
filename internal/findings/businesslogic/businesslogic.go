// Package businesslogic implements F13: business-logic surface mapping.
//
// The existing pipeline has `manual_business_logic_review.txt` which
// greps URLs for checkout/payment/coupon keywords. That surface map
// is useful but too narrow — it doesn't distinguish between a static
// info page about coupons and an actual coupon-application endpoint.
//
// This module does three things on top of the URL filter:
//
//  1. CATEGORIZE — re-classify each URL containing business-logic
//     keywords into one of: pricing, coupon, balance, vote, gift,
//     payment, currency, points. Each category gets its own severity
//     heuristic.
//
//  2. PARAM-SHAPE — look for parameters that suggest a backend state
//     mutation: quantity=negative, price=0, currency=USD-but-priced-
//     in-EUR, role=admin, etc. The presence of these params is a
//     "high-value target" signal for the hunter to test manually.
//
//  3. WRITE — a structured business_logic_findings.txt the hunter
//     can sort by severity, plus the raw URLs the existing
//     manual_business_logic_review.txt consumes.
//
// Output: business_logic_findings.txt
//
//	severity\thost\tpath\thint\tparams
//
// `params` is a comma-separated list of suspicious query param names
// observed at that URL — `quantity`, `price`, `coupon`, `currency`,
// `balance`, `role`, `admin`. Empty list = still reportable, just
// lower-priority.
package businesslogic

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

// category describes one business-logic class.
type category struct {
	name     string
	keywords []string
	severity string
	hint     string
}

var categories = []category{
	{
		name:     "pricing",
		keywords: []string{"checkout", "price", "pricing", "cart", "basket", "order", "purchase"},
		severity: "MEDIUM",
		hint:     "price manipulation: negative quantity, total bypass, currency confusion",
	},
	{
		name:     "coupon",
		keywords: []string{"coupon", "promo", "promocode", "discount", "voucher"},
		severity: "HIGH",
		hint:     "coupon double-spend via race; coupon on already-discounted item",
	},
	{
		name:     "balance",
		keywords: []string{"transfer", "wallet", "balance", "credit", "deposit", "withdraw", "redeem"},
		severity: "HIGH",
		hint:     "balance race; negative-amount transfer; integer overflow",
	},
	{
		name:     "vote",
		keywords: []string{"vote", "like", "upvote", "downvote", "thumbs", "reaction", "poll"},
		severity: "MEDIUM",
		hint:     "vote-doubling race; client-side count tamper",
	},
	{
		name:     "gift",
		keywords: []string{"gift", "giftcard", "gift-card", "claim", "redeem-gift"},
		severity: "HIGH",
		hint:     "gift-card redemption race; gift card for negative amount",
	},
	{
		name:     "payment",
		keywords: []string{"payment", "pay", "billing", "invoice", "charge", "refund", "stripe", "paypal"},
		severity: "MEDIUM",
		hint:     "payment amount tampering; refund race; free-trial reuse",
	},
	{
		name:     "currency",
		keywords: []string{"currency", "fx", "exchange", "conversion"},
		severity: "MEDIUM",
		hint:     "currency mismatch; integer-truncation in FX conversion",
	},
	{
		name:     "points",
		keywords: []string{"points", "loyalty", "rewards", "miles", "credits"},
		severity: "MEDIUM",
		hint:     "points race; negative redemption",
	},
}

// suspiciousParams are query parameter names that, when present at a
// business-logic URL, raise its priority. We don't run the actual
// attack — we just flag the URL for manual review.
var suspiciousParams = map[string]string{
	"quantity":  "negative-quantity price manipulation",
	"qty":       "negative-quantity price manipulation",
	"amount":    "amount tampering",
	"price":     "price tampering",
	"total":     "total bypass",
	"discount":  "discount manipulation",
	"coupon":    "coupon apply",
	"promo":     "coupon apply",
	"code":      "coupon/promo code injection",
	"currency":  "currency confusion",
	"balance":   "balance race",
	"credit":    "credit race",
	"role":      "vertical privilege escalation",
	"admin":     "vertical privilege escalation",
	"is_admin":    "vertical privilege escalation",
	"is_staff":    "vertical privilege escalation",
	"is_internal": "vertical privilege escalation",
	"user_id":   "horizontal IDOR",
	"account_id": "horizontal IDOR",
	"uid":       "horizontal IDOR",
}

// Run is the entry point. workDir is the rfuf work dir.
func Run(workDir string) error {
	urls, err := iohelp.ReadLines(workDir + "/all_urls.txt")
	if err != nil {
		return fmt.Errorf("read all_urls.txt: %w", err)
	}
	if len(urls) == 0 {
		return iohelp.WriteLines(workDir+"/business_logic_findings.txt", nil)
	}

	type hit struct {
		url      string
		cat      string
		severity string
		hint     string
		params   []string
	}
	seen := map[string]bool{}
	var hits []hit

	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		pathLower := strings.ToLower(u.Path)
		q := u.Query()
		sus := suspiciousParamsAt(q, pathLower)
		// Sort the param list for stable output.
		sort.Strings(sus)

		// Match the URL against category keywords.
		matched := false
		for _, c := range categories {
			for _, kw := range c.keywords {
				if strings.Contains(pathLower, kw) {
					if seen[raw+"|"+c.name] {
						break
					}
					seen[raw+"|"+c.name] = true
					hits = append(hits, hit{
						url:      raw,
						cat:      c.name,
						severity: c.severity,
						hint:     c.hint,
						params:   sus,
					})
					matched = true
					break
				}
			}
		}
		if !matched && len(sus) > 0 {
			// Path didn't match a category but suspicious params are
			// present. Still report at LOW priority.
			if seen[raw+"|generic"] {
				continue
			}
			seen[raw+"|generic"] = true
			hits = append(hits, hit{
				url:      raw,
				cat:      "generic",
				severity: "LOW",
				hint:     "suspicious query param shape; review for input validation",
				params:   sus,
			})
		}
	}

	// Sort: HIGH > MEDIUM > LOW > INFO; stable on URL.
	sevOrder := map[string]int{"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
	sort.SliceStable(hits, func(i, j int) bool {
		ai, bj := sevOrder[hits[i].severity], sevOrder[hits[j].severity]
		if ai != bj {
			return ai < bj
		}
		return hits[i].url < hits[j].url
	})

	lines := make([]string, len(hits))
	for i, h := range hits {
		params := ""
		if len(h.params) > 0 {
			params = "params=" + strings.Join(h.params, ",")
		}
		lines[i] = fmt.Sprintf("%s\t%s\t%s\tcat=%s\t%s\thint=%s",
			h.severity, uHost(h.url), pathOnly(h.url),
			h.cat, params, h.hint)
	}
	return iohelp.WriteLines(workDir+"/business_logic_findings.txt", lines)
}

// suspiciousParamsAt returns the list of suspicious parameter names
// observed at u (case-insensitive). Only params present in the URL —
// we don't suggest "you might want to test quantity" if it's not
// there.
func suspiciousParamsAt(q url.Values, pathLower string) []string {
	var out []string
	for k := range q {
		// We also match against path segments (e.g. /admin/users).
		kl := strings.ToLower(k)
		if hint, ok := suspiciousParams[kl]; ok {
			_ = hint
			out = append(out, k)
			continue
		}
		if strings.Contains(pathLower, "/admin") {
			out = append(out, "admin-path-segment")
		}
	}
	return out
}

func uHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Host
}

func pathOnly(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Path
}