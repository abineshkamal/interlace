// Active scanning: Interlace sends crafted probe requests to a target and
// inspects the responses for injection vulnerabilities. Unlike passive checks,
// active scanning generates traffic, so callers MUST confirm the target host is
// in scope before invoking RunActive.
package scanner

import (
	_ "embed"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"interlace/internal/repeater"
)

//go:embed rules/active.json
var activeRulesJSON []byte

// maxProbes caps the number of requests a single active scan will send.
const maxProbes = 2000

// Rule is a JSON-defined active check.
type Rule struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Severity string   `json:"severity"`
	Type     string   `json:"type"` // "grep" | "reflection" | "redirect"
	Payloads []string `json:"payloads"`
	Grep     []string `json:"grep"`
	Detail   string   `json:"detail"`

	compiled []*regexp.Regexp
}

var defaultRules []Rule

func init() {
	if err := json.Unmarshal(activeRulesJSON, &defaultRules); err != nil {
		panic("scanner: invalid embedded active.json: " + err.Error())
	}
	for i := range defaultRules {
		for _, g := range defaultRules[i].Grep {
			re, err := regexp.Compile("(?i)" + g)
			if err != nil {
				panic(fmt.Sprintf("scanner: bad grep regex %q in rule %s: %v", g, defaultRules[i].ID, err))
			}
			defaultRules[i].compiled = append(defaultRules[i].compiled, re)
		}
	}
}

// Rules returns the loaded active rules (for display/counting).
func Rules() []Rule { return defaultRules }

// LoadRules reads additional active-check rules from every *.json file in dir
// (each a JSON array of rules, same format as the built-ins) and appends them.
// It returns the number of rules added. Missing dir is not an error.
func LoadRules(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	added := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return added, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		var rules []Rule
		if err := json.Unmarshal(b, &rules); err != nil {
			return added, fmt.Errorf("parse %s: %w", e.Name(), err)
		}
		for i := range rules {
			for _, g := range rules[i].Grep {
				re, err := regexp.Compile("(?i)" + g)
				if err != nil {
					return added, fmt.Errorf("%s: bad grep %q: %w", e.Name(), g, err)
				}
				rules[i].compiled = append(rules[i].compiled, re)
			}
			defaultRules = append(defaultRules, rules[i])
			added++
		}
	}
	return added, nil
}

// HostOf strips an optional port from a host authority.
func HostOf(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

// Target identifies what to scan.
type Target struct {
	Scheme string
	Host   string
	Raw    string // raw request template
}

// OOBClient mints out-of-band callback URLs and reports interactions, enabling
// blind (out-of-band) vulnerability detection. It may be nil to disable such checks.
type OOBClient interface {
	NewToken() (token, url string)
	Hits(token string) bool
}

type point struct {
	in   string // "query" or "body"
	name string
}

// RunActive scans the target's insertion points with all rules, emitting a
// Finding per confirmed issue. It returns the number of probe requests sent.
// oob may be nil to disable out-of-band (blind) checks.
func RunActive(ctx context.Context, t Target, sender *repeater.Sender, oob OOBClient, emit func(Finding)) (int, error) {
	req, err := parseRequest(t.Raw)
	if err != nil {
		return 0, err
	}
	points := req.insertionPoints()
	// Even with no parameter insertion points, request-level special checks
	// (host-header injection, cache poisoning, XXE, GraphQL, …) still apply.

	// Baseline response for differential grep checks.
	baseResp := sender.Send(ctx, repeater.Request{Scheme: t.Scheme, Host: t.Host, Raw: req.render(nil, "")})
	baseline := baseResp.Body

	type task struct {
		pt      point
		rule    Rule
		payload string
	}
	var tasks []task
	for _, pt := range points {
		for _, rule := range defaultRules {
			switch rule.Type {
			case "reflection":
				tasks = append(tasks, task{pt, rule, ""})
			case "oob":
				if oob != nil {
					tasks = append(tasks, task{pt, rule, ""})
				}
			case "boolean":
				tasks = append(tasks, task{pt, rule, ""}) // uses both payloads internally
			default:
				for _, pl := range rule.Payloads {
					tasks = append(tasks, task{pt, rule, pl})
				}
			}
		}
	}
	if len(tasks) > maxProbes {
		tasks = tasks[:maxProbes]
	}

	var (
		mu      sync.Mutex
		seen    = map[string]bool{}
		probes  int
		pending []pendingOOB // out-of-band checks to resolve after a grace period
	)
	report := func(f Finding) {
		mu.Lock()
		defer mu.Unlock()
		if seen[f.Key] {
			return
		}
		seen[f.Key] = true
		emit(f)
	}
	countProbe := func() { mu.Lock(); probes++; mu.Unlock() }
	isSeen := func(key string) bool { mu.Lock(); defer mu.Unlock(); return seen[key] }
	addPending := func(p pendingOOB) { mu.Lock(); pending = append(pending, p); mu.Unlock() }

	conc := 8
	jobs := make(chan task)
	var wg sync.WaitGroup
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for tk := range jobs {
				if ctx.Err() != nil {
					return
				}
				key := t.Host + "|" + req.path + "|" + tk.rule.ID + "|" + tk.pt.in + "|" + tk.pt.name
				if isSeen(key) {
					continue
				}
				probe(ctx, t, req, tk.pt, tk.rule, tk.payload, baseline, sender, oob, key, report, countProbe, addPending)
			}
		}()
	}
	for _, tk := range tasks {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return probes, ctx.Err()
		case jobs <- tk:
		}
	}
	close(jobs)
	wg.Wait()

	// Special checks that operate on the whole request body, not insertion points.
	if ctx.Err() == nil {
		checkXXE(ctx, t, req, sender, report, &probes, &mu)
		checkProtoPollution(ctx, t, req, sender, report, &probes, &mu)
		checkGraphQL(ctx, t, req, sender, report, &probes, &mu)
		checkHostHeader(ctx, t, req, sender, report, &probes, &mu)
		checkCachePoisoning(ctx, t, req, sender, report, &probes, &mu)
		checkDeser(ctx, t, req, sender, report, &probes, &mu)
	}

	// Resolve out-of-band checks: give callbacks a moment to arrive.
	if len(pending) > 0 && oob != nil {
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
		for _, p := range pending {
			if oob.Hits(p.token) {
				report(Finding{
					Severity: p.rule.Severity, Check: p.rule.ID, Title: p.rule.Name,
					Detail: p.rule.Detail, Evidence: p.evidence, Source: "active", Key: p.key,
				})
			}
		}
	}
	return probes, nil
}

type pendingOOB struct {
	key      string
	token    string
	rule     Rule
	evidence string
}

var passwdRe = regexp.MustCompile(`root:.*:0:0:`)
var deserRe = regexp.MustCompile(`(?i)(java\.io\.(Invalid(Class|Object)|StreamCorrupted)Exception|ObjectInputStream|ClassNotFoundException|__PHP_Incomplete_Class|unserialize\(\)|pickle|yaml\.load)`)

// checkDeser tests body-accepting endpoints for insecure deserialization by
// replacing the body with known serialized-object payloads.
func checkDeser(ctx context.Context, t Target, req *request, sender *repeater.Sender, report func(Finding), probes *int, mu *sync.Mutex) {
	switch req.method {
	case "POST", "PUT", "PATCH":
	default:
		return
	}
	payloads := []string{"rO0ABXQABHRlc3Q=", "O:8:\"stdClass\":0:{}", "(dp0\nS'a'\np1\nI1\ns."}
	for _, pl := range payloads {
		if ctx.Err() != nil {
			return
		}
		resp := sender.Send(ctx, repeater.Request{Scheme: t.Scheme, Host: t.Host, Raw: req.renderBody(pl)})
		mu.Lock()
		*probes++
		mu.Unlock()
		if resp.Error == "" && deserRe.MatchString(resp.Body) {
			report(Finding{
				Severity: High, Check: "insecure-deser", Title: "Insecure Deserialization",
				Detail:   "A serialized-object payload triggered a deserialization error, indicating the endpoint deserializes untrusted input.",
				Evidence: "serialized payload caused a deserialization error", Source: "active",
				Key: "insecure-deser|" + t.Host + "|" + req.path,
			})
			return
		}
	}
}

// checkXXE tests XML-accepting endpoints for external entity injection.
func checkXXE(ctx context.Context, t Target, req *request, sender *repeater.Sender, report func(Finding), probes *int, mu *sync.Mutex) {
	isXML := strings.Contains(req.contentType, "xml") || strings.HasPrefix(strings.TrimSpace(req.rawBodyRaw), "<")
	if !isXML {
		return
	}
	payload := `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>`
	raw := req.renderBody(payload)
	resp := sender.Send(ctx, repeater.Request{Scheme: t.Scheme, Host: t.Host, Raw: raw})
	mu.Lock()
	*probes++
	mu.Unlock()
	if resp.Error == "" && passwdRe.MatchString(resp.Body) {
		report(Finding{
			Severity: High, Check: "xxe", Title: "XML External Entity (XXE) Injection",
			Detail:   "An external entity referencing /etc/passwd was resolved and returned in the response.",
			Evidence: "XXE payload returned file contents", Source: "active",
			Key: "xxe|" + t.Host + "|" + req.path,
		})
	}
}

// checkProtoPollution tests JSON endpoints for prototype pollution using a
// pollute-then-observe technique.
func checkProtoPollution(ctx context.Context, t Target, req *request, sender *repeater.Sender, report func(Finding), probes *int, mu *sync.Mutex) {
	if !req.isJSON {
		return
	}
	// Baseline clean response.
	base := sender.Send(ctx, repeater.Request{Scheme: t.Scheme, Host: t.Host, Raw: req.render(nil, "")})
	// Send a polluting body.
	polluted := `{"__proto__":{"ilxPolluted":"ILXPP1337"}}`
	resp := sender.Send(ctx, repeater.Request{Scheme: t.Scheme, Host: t.Host, Raw: req.renderBody(polluted)})
	mu.Lock()
	*probes += 2
	mu.Unlock()
	if resp.Error != "" {
		return
	}
	// Evidence: the marker is reflected as a new property that was absent in the
	// baseline (indicating the prototype was polluted and leaked back).
	if strings.Contains(resp.Body, "ILXPP1337") && !strings.Contains(base.Body, "ILXPP1337") {
		report(Finding{
			Severity: Medium, Check: "proto-pollution", Title: "Prototype Pollution",
			Detail:   "A __proto__ payload was accepted and reflected as a new global property, indicating prototype pollution.",
			Evidence: "injected __proto__.ilxPolluted appeared in the response", Source: "active",
			Key: "proto-pollution|" + t.Host + "|" + req.path,
		})
	}
}

func probe(ctx context.Context, t Target, req *request, pt point, rule Rule, payload, baseline string,
	sender *repeater.Sender, oob OOBClient, key string, report func(Finding), countProbe func(), addPending func(pendingOOB)) {

	var injected string
	var token string
	var oobToken string
	switch rule.Type {
	case "reflection":
		token = "ilx" + randToken()
		injected = token + "'\"><svg/ilxss=1>"
	case "oob":
		if oob == nil {
			return
		}
		var url string
		oobToken, url = oob.NewToken()
		injected = url
	default:
		injected = payload
	}

	raw := req.render(&pt, injected)
	resp := sender.Send(ctx, repeater.Request{Scheme: t.Scheme, Host: t.Host, Raw: raw})
	countProbe()
	if resp.Error != "" {
		return
	}

	evidence := fmt.Sprintf("param %q (%s), payload: %s", pt.name, pt.in, injected)
	mk := func(sev string) Finding {
		return Finding{
			Severity: sev, Check: rule.ID, Title: rule.Name, Detail: rule.Detail,
			Evidence: evidence, Source: "active", Key: key,
		}
	}

	switch rule.Type {
	case "grep":
		for _, re := range rule.compiled {
			if re.MatchString(resp.Body) && !re.MatchString(baseline) {
				f := mk(rule.Severity)
				f.Evidence = evidence + "  →  matched: " + re.String()
				report(f)
				return
			}
		}
	case "header-grep":
		for _, re := range rule.compiled {
			if re.MatchString(resp.Headers) {
				f := mk(rule.Severity)
				f.Evidence = evidence + "  →  injected response header"
				report(f)
				return
			}
		}
	case "reflection":
		// Only meaningful in an HTML context; a JSON API echoing input verbatim
		// is not XSS.
		if !strings.Contains(strings.ToLower(headerValue(resp.Headers, "content-type")), "text/html") {
			return
		}
		needle := token + "'\"><svg/ilxss=1>"
		if strings.Contains(resp.Body, needle) {
			report(mk(rule.Severity))
		}
	case "redirect":
		if loc := locationHeader(resp.Headers); loc != "" {
			if strings.Contains(loc, "interlace-oob.example") &&
				(strings.HasPrefix(loc, "http") || strings.HasPrefix(loc, "//")) {
				f := mk(rule.Severity)
				f.Evidence = evidence + "  →  Location: " + loc
				report(f)
			}
		}
	case "oob":
		// Detection is deferred: register the token to check after a grace period.
		addPending(pendingOOB{key: key, token: oobToken, rule: rule, evidence: evidence})
	case "time":
		// Response delayed by the injected sleep (~5s) indicates blind SQLi.
		if resp.DurationMs >= 4000 {
			f := mk(rule.Severity)
			f.Evidence = evidence + fmt.Sprintf("  →  response delayed %dms", resp.DurationMs)
			report(f)
		}
	case "boolean":
		// Compare a true vs false condition at this point.
		if len(rule.Payloads) < 2 {
			return
		}
		rawT := req.render(&pt, rule.Payloads[0])
		rawF := req.render(&pt, rule.Payloads[1])
		rt := sender.Send(ctx, repeater.Request{Scheme: t.Scheme, Host: t.Host, Raw: rawT})
		rf := sender.Send(ctx, repeater.Request{Scheme: t.Scheme, Host: t.Host, Raw: rawF})
		if rt.Error != "" || rf.Error != "" {
			return
		}
		if rt.BodyLen != rf.BodyLen && absInt(rt.BodyLen-rf.BodyLen) > 8 {
			f := mk(rule.Severity)
			f.Evidence = fmt.Sprintf("param %q (%s): true=%db, false=%db", pt.name, pt.in, rt.BodyLen, rf.BodyLen)
			report(f)
		}
	}
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// --- request parsing / rendering ---

type request struct {
	method  string
	path    string
	query   url.Values
	qkeys   []string
	headers []string // "Name: Value", Accept-Encoding/Content-Length/Cookie excluded
	host    string

	contentType string
	rawBodyRaw  string // original body regardless of type

	cookies  []cookiePair // parsed Cookie header
	isForm   bool
	body     url.Values
	bkeys    []string
	isJSON   bool
	jsonObj  map[string]any
	jsonKeys []string
	rawBody  string
}

type cookiePair struct{ name, value string }

func parseRequest(raw string) (*request, error) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	head := raw
	body := ""
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		head = raw[:i]
		body = raw[i+2:]
	}
	lines := strings.Split(head, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, fmt.Errorf("empty request line")
	}
	parts := strings.Fields(strings.TrimSpace(lines[0]))
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed request line")
	}
	r := &request{method: parts[0]}
	reqURI := parts[1]
	if q := strings.IndexByte(reqURI, '?'); q >= 0 {
		r.path = reqURI[:q]
		r.query, _ = url.ParseQuery(reqURI[q+1:])
	} else {
		r.path = reqURI
		r.query = url.Values{}
	}
	for k := range r.query {
		r.qkeys = append(r.qkeys, k)
	}

	var contentType string
	for _, ln := range lines[1:] {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		c := strings.IndexByte(ln, ':')
		if c < 0 {
			continue
		}
		name := strings.TrimSpace(ln[:c])
		val := strings.TrimSpace(ln[c+1:])
		switch strings.ToLower(name) {
		case "accept-encoding":
			continue // force plaintext responses for reliable detection
		case "content-length":
			continue // recomputed downstream
		case "host":
			r.host = val
		case "content-type":
			contentType = strings.ToLower(val)
		case "cookie":
			for _, c := range strings.Split(val, ";") {
				c = strings.TrimSpace(c)
				if eq := strings.IndexByte(c, '='); eq >= 0 {
					r.cookies = append(r.cookies, cookiePair{c[:eq], c[eq+1:]})
				}
			}
			continue // rebuilt in render
		}
		r.headers = append(r.headers, name+": "+val)
	}

	r.contentType = contentType
	r.rawBodyRaw = body
	switch {
	case strings.Contains(contentType, "application/x-www-form-urlencoded") && body != "":
		r.isForm = true
		r.body, _ = url.ParseQuery(body)
		for k := range r.body {
			r.bkeys = append(r.bkeys, k)
		}
	case strings.Contains(contentType, "application/json") && body != "":
		if json.Unmarshal([]byte(body), &r.jsonObj) == nil {
			r.isJSON = true
			for k, v := range r.jsonObj {
				if _, ok := v.(string); ok { // inject into string fields only
					r.jsonKeys = append(r.jsonKeys, k)
				}
			}
		} else {
			r.rawBody = body
		}
	default:
		r.rawBody = body
	}
	return r, nil
}

func (r *request) insertionPoints() []point {
	var pts []point
	for _, k := range r.qkeys {
		pts = append(pts, point{"query", k})
	}
	for _, k := range r.bkeys {
		pts = append(pts, point{"body", k})
	}
	for _, c := range r.cookies {
		pts = append(pts, point{"cookie", c.name})
	}
	for _, k := range r.jsonKeys {
		pts = append(pts, point{"json", k})
	}
	return pts
}

// render rebuilds the raw request, injecting value at pt (nil pt = baseline).
func (r *request) render(pt *point, value string) string {
	q := cloneValues(r.query)
	b := cloneValues(r.body)
	if pt != nil {
		switch pt.in {
		case "query":
			q.Set(pt.name, value)
		case "body":
			b.Set(pt.name, value)
		}
	}
	line := r.method + " " + r.path
	if len(q) > 0 {
		line += "?" + q.Encode()
	}
	line += " HTTP/1.1"

	var sb strings.Builder
	sb.WriteString(line + "\r\n")
	for _, h := range r.headers {
		sb.WriteString(h + "\r\n")
	}
	// Rebuild the Cookie header, injecting into the targeted cookie.
	if len(r.cookies) > 0 {
		var parts []string
		for _, c := range r.cookies {
			v := c.value
			if pt != nil && pt.in == "cookie" && pt.name == c.name {
				v = value
			}
			parts = append(parts, c.name+"="+v)
		}
		sb.WriteString("Cookie: " + strings.Join(parts, "; ") + "\r\n")
	}
	sb.WriteString("\r\n")
	switch {
	case r.isForm:
		sb.WriteString(b.Encode())
	case r.isJSON:
		obj := make(map[string]any, len(r.jsonObj))
		for k, v := range r.jsonObj {
			obj[k] = v
		}
		if pt != nil && pt.in == "json" {
			obj[pt.name] = value
		}
		if bs, err := json.Marshal(obj); err == nil {
			sb.Write(bs)
		}
	default:
		sb.WriteString(r.rawBody)
	}
	return sb.String()
}

// checkGraphQL detects a GraphQL endpoint and tests whether schema
// introspection is exposed.
func checkGraphQL(ctx context.Context, t Target, req *request, sender *repeater.Sender, report func(Finding), probes *int, mu *sync.Mutex) {
	isGQL := strings.Contains(strings.ToLower(req.path), "graphql") ||
		strings.Contains(req.contentType, "graphql") ||
		(req.isJSON && strings.Contains(req.rawBodyRaw, "query"))
	if !isGQL {
		return
	}
	// Report the endpoint, then test introspection with a POST JSON query.
	report(Finding{
		Severity: Info, Check: "graphql-endpoint", Title: "GraphQL endpoint",
		Detail:   "A GraphQL endpoint was identified; review its queries/mutations and authorization.",
		Evidence: req.method + " " + req.path, Source: "active",
		Key: "graphql-endpoint|" + t.Host + "|" + req.path,
	})

	method := "POST"
	path := req.path
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	body := `{"query":"query{__schema{queryType{name} types{name}}}"}`
	raw := method + " " + path + " HTTP/1.1\r\nHost: " + t.Host + "\r\nContent-Type: application/json\r\n\r\n" + body
	resp := sender.Send(ctx, repeater.Request{Scheme: t.Scheme, Host: t.Host, Raw: raw})
	mu.Lock()
	*probes++
	mu.Unlock()
	if resp.Error == "" && strings.Contains(resp.Body, "__schema") && strings.Contains(resp.Body, "queryType") {
		report(Finding{
			Severity: Medium, Check: "graphql-introspection", Title: "GraphQL introspection enabled",
			Detail:   "Schema introspection is enabled, exposing the full API schema (types, queries, mutations) to any client. Disable it in production.",
			Evidence: "introspection query returned __schema", Source: "active",
			Key: "graphql-introspection|" + t.Host + "|" + path,
		})
	}
}

// renderHeaders rebuilds the raw request overriding/adding the given headers
// (case-insensitive), keeping the original body.
func (r *request) renderHeaders(override map[string]string) string {
	lower := map[string]string{}
	for k, v := range override {
		lower[strings.ToLower(k)] = v
	}
	var sb strings.Builder
	sb.WriteString(r.method + " " + r.path)
	if len(r.query) > 0 {
		sb.WriteString("?" + r.query.Encode())
	}
	sb.WriteString(" HTTP/1.1\r\n")
	seen := map[string]bool{}
	for _, h := range r.headers {
		name := h
		if c := strings.IndexByte(h, ':'); c >= 0 {
			name = strings.TrimSpace(h[:c])
		}
		ln := strings.ToLower(name)
		if v, ok := lower[ln]; ok {
			sb.WriteString(name + ": " + v + "\r\n")
			seen[ln] = true
		} else {
			sb.WriteString(h + "\r\n")
		}
	}
	for k, v := range override {
		if !seen[strings.ToLower(k)] {
			sb.WriteString(k + ": " + v + "\r\n")
		}
	}
	if len(r.cookies) > 0 {
		var parts []string
		for _, c := range r.cookies {
			parts = append(parts, c.name+"="+c.value)
		}
		sb.WriteString("Cookie: " + strings.Join(parts, "; ") + "\r\n")
	}
	sb.WriteString("\r\n")
	switch {
	case r.isForm:
		sb.WriteString(r.body.Encode())
	case r.isJSON:
		if bs, err := json.Marshal(r.jsonObj); err == nil {
			sb.Write(bs)
		}
	default:
		sb.WriteString(r.rawBody)
	}
	return sb.String()
}

// checkHostHeader tests whether the Host header is reflected (host-header injection).
func checkHostHeader(ctx context.Context, t Target, req *request, sender *repeater.Sender, report func(Finding), probes *int, mu *sync.Mutex) {
	marker := "interlace-hhi.example"
	resp := sender.Send(ctx, repeater.Request{Scheme: t.Scheme, Host: t.Host, Raw: req.renderHeaders(map[string]string{"Host": marker})})
	mu.Lock()
	*probes++
	mu.Unlock()
	if resp.Error == "" && (strings.Contains(resp.Body, marker) || strings.Contains(resp.Headers, marker)) {
		report(Finding{
			Severity: Medium, Check: "host-header-injection", Title: "Host Header Injection",
			Detail:   "An attacker-controlled Host header was reflected into the response (body or a redirect), which can enable password-reset poisoning and cache attacks.",
			Evidence: "Host: " + marker + " reflected", Source: "active",
			Key: "host-header-injection|" + t.Host + "|" + req.path,
		})
	}
}

// checkCachePoisoning tests whether an unkeyed header is reflected in a cacheable response.
func checkCachePoisoning(ctx context.Context, t Target, req *request, sender *repeater.Sender, report func(Finding), probes *int, mu *sync.Mutex) {
	marker := "interlace-cp.example"
	resp := sender.Send(ctx, repeater.Request{Scheme: t.Scheme, Host: t.Host, Raw: req.renderHeaders(map[string]string{"X-Forwarded-Host": marker})})
	mu.Lock()
	*probes++
	mu.Unlock()
	if resp.Error != "" {
		return
	}
	reflected := strings.Contains(resp.Body, marker) || strings.Contains(resp.Headers, marker)
	cc := strings.ToLower(headerValue(resp.Headers, "cache-control"))
	cacheable := !strings.Contains(cc, "no-store") && !strings.Contains(cc, "private") && !strings.Contains(cc, "no-cache")
	if reflected && cacheable {
		report(Finding{
			Severity: Medium, Check: "cache-poisoning", Title: "Potential Web Cache Poisoning",
			Detail:   "An unkeyed request header (X-Forwarded-Host) was reflected in a cacheable response, which can poison the shared cache for other users.",
			Evidence: "X-Forwarded-Host: " + marker + " reflected in a cacheable response", Source: "active",
			Key: "cache-poisoning|" + t.Host + "|" + req.path,
		})
	}
}

// renderBody rebuilds the raw request with body replaced (for XXE/PP payloads).
func (r *request) renderBody(body string) string {
	var sb strings.Builder
	sb.WriteString(r.method + " " + r.path)
	if len(r.query) > 0 {
		sb.WriteString("?" + r.query.Encode())
	}
	sb.WriteString(" HTTP/1.1\r\n")
	for _, h := range r.headers {
		sb.WriteString(h + "\r\n")
	}
	if len(r.cookies) > 0 {
		var parts []string
		for _, c := range r.cookies {
			parts = append(parts, c.name+"="+c.value)
		}
		sb.WriteString("Cookie: " + strings.Join(parts, "; ") + "\r\n")
	}
	sb.WriteString("\r\n")
	sb.WriteString(body)
	return sb.String()
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vals := range v {
		out[k] = append([]string(nil), vals...)
	}
	return out
}

func locationHeader(headers string) string {
	return headerValue(headers, "location")
}

func headerValue(headers, name string) string {
	name = strings.ToLower(name) + ":"
	for _, ln := range strings.Split(headers, "\n") {
		if strings.HasPrefix(strings.ToLower(ln), name) {
			return strings.TrimSpace(ln[len(name):])
		}
	}
	return ""
}

var tokenCounter int
var tokenMu sync.Mutex

func randToken() string {
	tokenMu.Lock()
	tokenCounter++
	n := tokenCounter
	tokenMu.Unlock()
	return fmt.Sprintf("%d%d", time.Now().UnixNano()%100000, n)
}
