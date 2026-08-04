// Package idor implements F5: IDOR surface mapping.
//
// Real IDOR findings need two authenticated test accounts and a manual
// "swap the ID and see if the other user sees the response" test. We
// can't do that — the tool has no concept of authentication. What we
// CAN do is build a high-signal candidate list:
//
//   1. Group every URL in all_urls.txt by the *name* of its object-
//      reference parameter (id, user_id, account_id, ...).
//   2. For each group, count the number of distinct hosts and the
//      number of distinct IDs observed.
//   3. Emit groups where (a) the param name is on our candidate list
//      AND (b) the group spans ≥2 hosts or has ≥3 distinct IDs.
//
// A surface-map entry means: "this parameter on this kind of URL is
// used in enough places to be worth setting up two test accounts for."
// That's exactly the triage list a real hunter would build by hand.
//
// Output:
//   - idor_surface.csv   with columns: param,host_count,id_count,
//                        example_url,hosts
//   - idor_surface.txt   same data, tab-separated, with severity
package idor

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

// objectRefParams are the parameter names we treat as object
// references. Mirrors paramshape.candidateParams but trimmed — the
// surface map only cares about params that are likely to map to a
// user/account/order/etc. object in the backend.
var objectRefParams = map[string]bool{
	"id":            true,
	"uid":           true,
	"user_id":       true,
	"userid":        true,
	"account_id":    true,
	"account":       true,
	"acct":          true,
	"order_id":      true,
	"orderid":       true,
	"doc_id":        true,
	"docid":         true,
	"document":      true,
	"document_id":   true,
	"file_id":       true,
	"fileid":        true,
	"file":          true,
	"product_id":    true,
	"productid":     true,
	"pid":           true,
	"article_id":    true,
	"articleid":     true,
	"msg_id":        true,
	"message_id":    true,
	"messageid":     true,
	"profile_id":    true,
	"profileid":     true,
	"booking_id":    true,
	"reservation":   true,
	"reservation_id": true,
	"invoice":       true,
	"invoice_id":    true,
	"invoiceid":     true,
	"comment_id":    true,
	"commentid":     true,
	"post_id":       true,
	"postid":        true,
	"report_id":     true,
	"reportid":      true,
	"category_id":   true,
	"categoryid":    true,
	"item_id":       true,
	"itemid":        true,
	"news_id":       true,
	"newsid":        true,
	"page_id":       true,
	"pageid":        true,
	"customer_id":   true,
	"customerid":    true,
	"client_id":     true,
	"clientid":      true,
	"member_id":     true,
	"memberid":      true,
	"tenant_id":     true,
	"tenantid":      true,
	"org_id":        true,
	"orgid":         true,
	"workspace_id":  true,
	"workspaceid":   true,
	"team_id":       true,
	"teamid":        true,
	"project_id":    true,
	"projectid":     true,
	"record_id":     true,
	"recordid":      true,
	"entity_id":     true,
	"entityid":      true,
	"object_id":     true,
	"objectid":      true,
	"resource_id":   true,
	"resourceid":    true,
}

// paramGroup accumulates host/id info for one parameter name.
type paramGroup struct {
	param    string
	hosts    map[string]struct{}
	ids      map[string]struct{}
	firstURL string
}

// Run is the entry point. workDir is the rfuf work dir.
func Run(workDir string) error {
	urls, err := iohelp.ReadLines(workDir + "/all_urls.txt")
	if err != nil {
		return fmt.Errorf("read all_urls.txt: %w", err)
	}
	if len(urls) == 0 {
		empty := []string{}
		_ = iohelp.WriteLines(workDir+"/idor_surface.csv", empty)
		return iohelp.WriteLines(workDir+"/idor_surface.txt", empty)
	}

	groups := map[string]*paramGroup{}
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		q := u.Query()
		if len(q) == 0 {
			continue
		}
		host := u.Host
		for name, vs := range q {
			if !objectRefParams[strings.ToLower(name)] {
				continue
			}
			g, ok := groups[name]
			if !ok {
				g = &paramGroup{
					param: name,
					hosts: map[string]struct{}{},
					ids:   map[string]struct{}{},
				}
				groups[name] = g
			}
			g.hosts[host] = struct{}{}
			if g.firstURL == "" {
				g.firstURL = raw
			}
			for _, v := range vs {
				if v != "" {
					g.ids[v] = struct{}{}
				}
			}
		}
	}

	var csvLines, txtLines []string
	csvLines = append(csvLines, "param,host_count,id_count,example_url")
	// Sort by host_count desc, then id_count desc — top candidates first.
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		gi, gj := groups[keys[i]], groups[keys[j]]
		if len(gi.hosts) != len(gj.hosts) {
			return len(gi.hosts) > len(gj.hosts)
		}
		return len(gi.ids) > len(gj.ids)
	})
	for _, k := range keys {
		g := groups[k]
		// Heuristic threshold: at least 2 hosts OR at least 3 IDs.
		// Single-host / single-id URLs are background noise.
		if len(g.hosts) < 2 && len(g.ids) < 3 {
			continue
		}
		hostList := make([]string, 0, len(g.hosts))
		for h := range g.hosts {
			hostList = append(hostList, h)
		}
		sort.Strings(hostList)
		csvLines = append(csvLines, fmt.Sprintf("%s,%d,%d,%s",
			g.param, len(g.hosts), len(g.ids), g.firstURL))
		severity := "MEDIUM"
		if len(g.hosts) >= 5 || len(g.ids) >= 10 {
			severity = "HIGH"
		}
		txtLines = append(txtLines, fmt.Sprintf("%s\t%s\thosts=%d\tids=%d\texample=%s\thosts_list=%s",
			g.param, severity, len(g.hosts), len(g.ids), g.firstURL, strings.Join(hostList, ",")))
	}

	if err := iohelp.WriteLines(workDir+"/idor_surface.csv", csvLines); err != nil {
		return err
	}
	return iohelp.WriteLines(workDir+"/idor_surface.txt", txtLines)
}
