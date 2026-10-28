// Package graphql probes discovered GraphQL endpoints for enabled schema
// introspection and, when it is open, synthesizes testable operation targets.
//
// Modern SPA/API targets are overwhelmingly GraphQL, yet the pipeline only ran
// a template scan against /graphql without ever sending an introspection query.
// This finder sends the standard __schema query to each candidate endpoint;
// when the server answers with a schema, that is a reportable finding (an
// unauthenticated/over-permissive introspection surface) and the enumerated
// query/mutation names become operator-review targets for authz/IDOR testing.
//
// Outputs:
//   - graphql_findings.txt   confirmed introspection-enabled endpoints (one row each)
//   - graphql_targets.txt     the confirmed endpoint URLs (for downstream use)
//   - graphql_candidates.txt  synthesized <url>\top=<name> rows (untested leads)
package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

// commonPaths are the GraphQL endpoint locations tried on every alive host.
var commonPaths = []string{"/graphql", "/api/graphql", "/v1/graphql", "/graphql/console", "/query", "/gql"}

// introspectionQuery lists the query/mutation field names so we can both detect
// introspection and count the exposed operations.
const introspectionQuery = `{"query":"query{__schema{queryType{fields{name}} mutationType{fields{name}}}}"}`

const hostCap = 200

// Run is the entry point. Reads alive.txt + js_endpoints.txt, writes the three
// graphql_* outputs.
func Run(workDir string) error {
	candidates := collectCandidates(workDir)

	findings := []string{}
	targets := []string{}
	leads := []string{}

	if len(candidates) == 0 {
		return writeAll(workDir, findings, targets, leads)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	client := &http.Client{Timeout: 8 * time.Second}
	iohelp.HardenClient(client)

	seen := map[string]bool{}
	for _, endpoint := range candidates {
		if seen[endpoint] {
			continue
		}
		seen[endpoint] = true
		queries, mutations, ok := introspect(ctx, client, endpoint)
		if !ok {
			continue
		}
		findings = append(findings, fmt.Sprintf("HIGH\t%s\tgraphql introspection enabled\tqueries=%d mutations=%d", endpoint, len(queries), len(mutations)))
		targets = append(targets, endpoint)
		for _, op := range append(queries, mutations...) {
			leads = append(leads, fmt.Sprintf("%s\top=%s\tvalidation=candidate", endpoint, op))
		}
	}
	return writeAll(workDir, findings, targets, leads)
}

// collectCandidates builds the endpoint list: every alive host crossed with the
// common GraphQL paths, plus any /graphql-bearing URL already discovered in JS.
func collectCandidates(workDir string) []string {
	var out []string
	hosts, _ := iohelp.ReadLines(workDir + "/alive.txt")
	if len(hosts) > hostCap {
		hosts = hosts[:hostCap]
	}
	for _, line := range hosts {
		raw := strings.Fields(line)
		if len(raw) == 0 {
			continue
		}
		u, err := url.Parse(raw[0])
		if err != nil || u.Host == "" {
			continue
		}
		base := u.Scheme + "://" + u.Host
		for _, p := range commonPaths {
			out = append(out, base+p)
		}
	}
	// JS-mined endpoints that already point at a graphql route.
	js, _ := iohelp.ReadLines(workDir + "/js_endpoints.txt")
	for _, line := range js {
		if strings.Contains(strings.ToLower(line), "graphql") || strings.Contains(strings.ToLower(line), "/gql") {
			if u, err := url.Parse(strings.Fields(line)[0]); err == nil && u.Host != "" {
				out = append(out, u.String())
			}
		}
	}
	return out
}

// introspect POSTs the introspection query and returns the query/mutation field
// names when the server exposes a schema. ok is false for any non-GraphQL or
// introspection-disabled response.
func introspect(ctx context.Context, client *http.Client, endpoint string) (queries, mutations []string, ok bool) {
	req, err := iohelp.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(introspectionQuery))
	if err != nil {
		return nil, nil, false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return decodeSchema(body)
}

// decodeSchema extracts query/mutation field names from a GraphQL introspection
// response body. ok is true only when a schema with at least one operation is
// present (split out from introspect so it can be unit-tested without the
// scope-gated network path).
func decodeSchema(body []byte) (queries, mutations []string, ok bool) {
	var parsed struct {
		Data struct {
			Schema struct {
				QueryType    struct{ Fields []struct{ Name string } } `json:"queryType"`
				MutationType struct{ Fields []struct{ Name string } } `json:"mutationType"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, nil, false
	}
	for _, f := range parsed.Data.Schema.QueryType.Fields {
		if f.Name != "" {
			queries = append(queries, f.Name)
		}
	}
	for _, f := range parsed.Data.Schema.MutationType.Fields {
		if f.Name != "" {
			mutations = append(mutations, f.Name)
		}
	}
	return queries, mutations, len(queries)+len(mutations) > 0
}

func writeAll(workDir string, findings, targets, leads []string) error {
	if err := iohelp.WriteLines(workDir+"/graphql_findings.txt", findings); err != nil {
		return err
	}
	if err := iohelp.WriteLines(workDir+"/graphql_targets.txt", targets); err != nil {
		return err
	}
	return iohelp.WriteLines(workDir+"/graphql_candidates.txt", leads)
}
