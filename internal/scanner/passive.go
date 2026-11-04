// Package scanner holds Interlace's passive security checks. Passive checks run
// on traffic the proxy has already captured — they never send new requests —
// and emit deduplicated findings.
package scanner

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"interlace/internal/model"
)

// Severity levels.
const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
	Info   = "info"
)

// Finding is a single passive-scan result.
type Finding struct {
	ID       int64     `json:"id"`
	FlowID   int64     `json:"flowId"`
	Time     time.Time `json:"time"`
	Severity string    `json:"severity"`
	Check    string    `json:"check"`
	Title    string    `json:"title"`
	Detail   string    `json:"detail"`
	Host     string    `json:"host"`
	URL      string    `json:"url"`
	Evidence string    `json:"evidence"`
	Source   string    `json:"source"` // "passive" or "active"
	Note     string    `json:"note"`   // analyst note / triage comment
	Key      string    `json:"-"`      // dedup key
}

// Scan runs all passive checks against a captured flow and returns any findings.
// Only successful responses are inspected.
func Scan(f *model.Flow) []Finding {
	if f.Error != "" || f.StatusCode == 0 {
		return nil
	}
	var out []Finding
	for _, chk := range checks {
		out = append(out, chk(f)...)
	}
	for i := range out {
		out[i].FlowID = f.ID
		out[i].Time = time.Now()
		out[i].Host = f.Host
		out[i].Source = "passive"
		if out[i].URL == "" {
			out[i].URL = f.URL
		}
	}
	return out
}

// a check inspects a flow and returns zero or more findings (Key, Severity,
// Check, Title, Detail, Evidence set; the rest filled by Scan).
type check func(*model.Flow) []Finding

var checks = []check{
	checkHSTS,
	checkCSP,
	checkFrameOptions,
	checkNoSniff,
	checkReferrerPolicy,
	checkCookies,
	checkCORS,
	checkInfoDisclosure,
	checkMixedContent,
	checkSecrets,
	checkJWT,
	checkCORSReflection,
	checkCacheable,
	checkTechFingerprint,
}

// checkTechFingerprint reports detected technologies (info) from headers and cookies.
func checkTechFingerprint(f *model.Flow) []Finding {
	var tech []string
	add := func(t string) {
		for _, e := range tech {
			if e == t {
				return
			}
		}
		tech = append(tech, t)
	}
	if v := f.RespHeaders.Get("Server"); v != "" {
		add("Server: " + v)
	}
	if v := f.RespHeaders.Get("X-Powered-By"); v != "" {
		add(v)
	}
	for h, label := range map[string]string{
		"X-AspNet-Version": "ASP.NET", "X-AspNetMvc-Version": "ASP.NET MVC",
		"X-Drupal-Cache": "Drupal", "X-Generator": "", "X-Shopify-Stage": "Shopify",
		"X-Magento-Cache-Debug": "Magento", "X-Varnish": "Varnish", "Via": "Proxy/CDN",
		"CF-Ray": "Cloudflare", "X-Served-By": "CDN", "X-Jenkins": "Jenkins",
	} {
		if v := f.RespHeaders.Get(h); v != "" {
			if label == "" {
				label = v
			}
			add(label)
		}
	}
	for _, sc := range f.RespHeaders["Set-Cookie"] {
		low := strings.ToLower(sc)
		for sig, label := range map[string]string{
			"phpsessid": "PHP", "jsessionid": "Java/JSP", "asp.net_sessionid": "ASP.NET",
			"laravel_session": "Laravel", "_rails": "Ruby on Rails", "connect.sid": "Node.js/Express",
			"django": "Django", "ci_session": "CodeIgniter",
		} {
			if strings.Contains(low, sig) {
				add(label)
			}
		}
	}
	if len(tech) == 0 {
		return nil
	}
	return one(Info, "tech-fingerprint", "Technology fingerprint",
		"Detected server-side technologies, useful for targeting known vulnerabilities.",
		strings.Join(tech, ", "), "tech-fingerprint|"+f.Host)
}

// checkCORSReflection flags responses that reflect the request Origin (or allow
// "null") in Access-Control-Allow-Origin — often a broken CORS policy.
func checkCORSReflection(f *model.Flow) []Finding {
	acao := f.RespHeaders.Get("Access-Control-Allow-Origin")
	if acao == "" || acao == "*" {
		return nil // wildcard handled by checkCORS
	}
	origin := f.ReqHeaders.Get("Origin")
	creds := strings.EqualFold(f.RespHeaders.Get("Access-Control-Allow-Credentials"), "true")
	if strings.EqualFold(acao, "null") {
		sev := Medium
		if creds {
			sev = High
		}
		return one(sev, "cors-null-origin", "CORS allows \"null\" origin",
			"The response allows the null origin, which sandboxed iframes and some attacker contexts can send"+credsNote(creds),
			"Access-Control-Allow-Origin: null", "cors-null-origin|"+f.Host)
	}
	if origin != "" && strings.EqualFold(acao, origin) {
		sev := Medium
		if creds {
			sev = High
		}
		return one(sev, "cors-origin-reflection", "CORS reflects the request Origin",
			"The response echoes the request's Origin in Access-Control-Allow-Origin, so any site can read cross-origin responses"+credsNote(creds),
			"Origin: "+origin+" → Access-Control-Allow-Origin: "+acao, "cors-origin-reflection|"+f.Host)
	}
	return nil
}

func credsNote(creds bool) string {
	if creds {
		return " — and with Access-Control-Allow-Credentials: true, authenticated data is exposed."
	}
	return "."
}

// checkCacheable flags sensitive responses (those that set a cookie or answer
// an authenticated request) that are not marked uncacheable.
func checkCacheable(f *model.Flow) []Finding {
	sensitive := len(f.RespHeaders["Set-Cookie"]) > 0 || f.ReqHeaders.Get("Authorization") != ""
	if !sensitive {
		return nil
	}
	cc := strings.ToLower(f.RespHeaders.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") || strings.Contains(cc, "no-cache") {
		return nil
	}
	return one(Low, "cacheable-sensitive", "Sensitive response may be cacheable",
		"A response that sets a cookie or answers an authenticated request lacks Cache-Control: no-store/private, so proxies or the browser may cache it.",
		"Cache-Control: "+f.RespHeaders.Get("Cache-Control"), "cacheable-sensitive|"+f.Host)
}

// secretPatterns are high-signal credential/token regexes scanned in responses.
var secretPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"AWS access key ID", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"Google API key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"GitHub token", regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36,}`)},
	{"Slack token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`)},
	{"Stripe secret key", regexp.MustCompile(`sk_live_[0-9A-Za-z]{20,}`)},
	{"Twilio API key", regexp.MustCompile(`SK[0-9a-fA-F]{32}`)},
	{"SendGrid API key", regexp.MustCompile(`SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}`)},
	{"npm access token", regexp.MustCompile(`npm_[0-9A-Za-z]{36}`)},
	{"Google OAuth token", regexp.MustCompile(`ya29\.[0-9A-Za-z_-]{20,}`)},
	{"Private key block", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)},
	{"Generic bearer secret", regexp.MustCompile(`(?i)(?:secret|api[_-]?key|access[_-]?token)"?\s*[:=]\s*"?[0-9A-Za-z\-_]{24,}`)},
}

// checkSecrets looks for exposed credentials/tokens in response bodies. Modern
// "secret scanning" that Burp leaves to extensions.
func checkSecrets(f *model.Flow) []Finding {
	body := decodeResponseBody(f)
	if body == nil {
		return nil
	}
	var out []Finding
	for _, p := range secretPatterns {
		if m := p.re.Find(body); m != nil {
			out = append(out, Finding{
				Severity: High, Check: "exposed-secret", Title: "Exposed secret: " + p.name,
				Detail:   "A value matching " + p.name + " was found in the response body. Exposed credentials should be rotated and removed from responses.",
				Evidence: redact(string(m)),
				Key:      "exposed-secret|" + f.Host + "|" + p.name,
			})
		}
	}
	return out
}

var jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`)

// checkJWT finds JSON Web Tokens in traffic and flags insecure algorithms.
func checkJWT(f *model.Flow) []Finding {
	// Look in both the response body and the request (Authorization/cookies).
	haystacks := [][]byte{decodeResponseBody(f), f.ReqBody, []byte(headerValuesJoined(f.ReqHeaders))}
	for _, hs := range haystacks {
		if hs == nil {
			continue
		}
		m := jwtRe.Find(hs)
		if m == nil {
			continue
		}
		parts := strings.Split(string(m), ".")
		alg := jwtAlg(parts[0])
		if strings.EqualFold(alg, "none") {
			return one(High, "jwt-alg-none", "JWT with alg:none",
				"A JWT using the \"none\" algorithm (unsigned) was observed; such tokens can be forged.",
				string(m), "jwt-alg-none|"+f.Host)
		}
		return one(Info, "jwt-observed", "JSON Web Token in use",
			"A JWT ("+alg+") is present in traffic. Verify signature strength and that secrets are not weak.",
			alg+" token", "jwt-observed|"+f.Host)
	}
	return nil
}

func jwtAlg(headerSeg string) string {
	b, err := base64.RawURLEncoding.DecodeString(headerSeg)
	if err != nil {
		if b2, e2 := base64.StdEncoding.DecodeString(headerSeg); e2 == nil {
			b = b2
		} else {
			return "unknown"
		}
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(b, &h) != nil || h.Alg == "" {
		return "unknown"
	}
	return h.Alg
}

func headerValuesJoined(h http.Header) string {
	var b strings.Builder
	for _, vv := range h {
		for _, v := range vv {
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// redact masks the middle of a matched secret for safe display.
func redact(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:6] + "…" + s[len(s)-4:]
}

func isHTML(f *model.Flow) bool {
	return strings.Contains(strings.ToLower(f.ContentType), "text/html")
}

func one(sev, chk, title, detail, evidence, key string) []Finding {
	return []Finding{{Severity: sev, Check: chk, Title: title, Detail: detail, Evidence: evidence, Key: key}}
}

func checkHSTS(f *model.Flow) []Finding {
	if f.Scheme != "https" {
		return nil
	}
	if f.RespHeaders.Get("Strict-Transport-Security") == "" {
		return one(Medium, "missing-hsts", "Missing HTTP Strict-Transport-Security",
			"The response over HTTPS does not set a Strict-Transport-Security (HSTS) header, so browsers are not told to enforce HTTPS for future requests.",
			"", "missing-hsts|"+f.Host)
	}
	return nil
}

func checkCSP(f *model.Flow) []Finding {
	if !isHTML(f) {
		return nil
	}
	if f.RespHeaders.Get("Content-Security-Policy") == "" {
		return one(Medium, "missing-csp", "Missing Content-Security-Policy",
			"This HTML response has no Content-Security-Policy header, weakening defense against cross-site scripting and data-injection attacks.",
			"", "missing-csp|"+f.Host)
	}
	return nil
}

func checkFrameOptions(f *model.Flow) []Finding {
	if !isHTML(f) {
		return nil
	}
	csp := strings.ToLower(f.RespHeaders.Get("Content-Security-Policy"))
	if f.RespHeaders.Get("X-Frame-Options") == "" && !strings.Contains(csp, "frame-ancestors") {
		return one(Medium, "missing-xfo", "Missing clickjacking protection",
			"No X-Frame-Options header and no CSP frame-ancestors directive, so the page can be framed by other sites (clickjacking).",
			"", "missing-xfo|"+f.Host)
	}
	return nil
}

func checkNoSniff(f *model.Flow) []Finding {
	v := strings.ToLower(f.RespHeaders.Get("X-Content-Type-Options"))
	if !strings.Contains(v, "nosniff") {
		return one(Low, "missing-nosniff", "Missing X-Content-Type-Options: nosniff",
			"Without nosniff, browsers may MIME-sniff the response and interpret it as a different content type.",
			"", "missing-nosniff|"+f.Host)
	}
	return nil
}

func checkReferrerPolicy(f *model.Flow) []Finding {
	if !isHTML(f) {
		return nil
	}
	if f.RespHeaders.Get("Referrer-Policy") == "" {
		return one(Info, "missing-referrer-policy", "Missing Referrer-Policy",
			"No Referrer-Policy header; the full URL may leak to third-party sites via the Referer header.",
			"", "missing-referrer-policy|"+f.Host)
	}
	return nil
}

func checkCookies(f *model.Flow) []Finding {
	var out []Finding
	for _, sc := range f.RespHeaders["Set-Cookie"] {
		name := sc
		if i := strings.IndexByte(sc, '='); i >= 0 {
			name = sc[:i]
		}
		name = strings.TrimSpace(name)
		low := strings.ToLower(sc)
		if f.Scheme == "https" && !strings.Contains(low, "secure") {
			out = append(out, Finding{Severity: Medium, Check: "cookie-no-secure",
				Title: "Cookie without Secure flag", Evidence: sc,
				Detail: fmt.Sprintf("Cookie %q is set over HTTPS without the Secure flag, so it can be sent over plain HTTP.", name),
				Key: "cookie-no-secure|" + f.Host + "|" + name})
		}
		if !strings.Contains(low, "httponly") {
			out = append(out, Finding{Severity: Low, Check: "cookie-no-httponly",
				Title: "Cookie without HttpOnly flag", Evidence: sc,
				Detail: fmt.Sprintf("Cookie %q lacks HttpOnly, so it is readable by JavaScript (document.cookie).", name),
				Key: "cookie-no-httponly|" + f.Host + "|" + name})
		}
		if !strings.Contains(low, "samesite") {
			out = append(out, Finding{Severity: Low, Check: "cookie-no-samesite",
				Title: "Cookie without SameSite attribute", Evidence: sc,
				Detail: fmt.Sprintf("Cookie %q has no SameSite attribute, which can enable cross-site request forgery.", name),
				Key: "cookie-no-samesite|" + f.Host + "|" + name})
		}
	}
	return out
}

func checkCORS(f *model.Flow) []Finding {
	acao := f.RespHeaders.Get("Access-Control-Allow-Origin")
	if acao != "*" {
		return nil
	}
	acac := strings.ToLower(f.RespHeaders.Get("Access-Control-Allow-Credentials"))
	if acac == "true" {
		return one(High, "cors-wildcard-credentials", "CORS: wildcard origin with credentials",
			"Access-Control-Allow-Origin is * together with Access-Control-Allow-Credentials: true. This is an insecure (and spec-invalid) combination that can expose authenticated data cross-origin.",
			"Access-Control-Allow-Origin: *", "cors-wildcard-credentials|"+f.Host)
	}
	return one(Low, "cors-wildcard", "CORS: wildcard Access-Control-Allow-Origin",
		"The response allows any origin (Access-Control-Allow-Origin: *). Confirm no sensitive data is served from this endpoint.",
		"Access-Control-Allow-Origin: *", "cors-wildcard|"+f.Host)
}

func checkInfoDisclosure(f *model.Flow) []Finding {
	var out []Finding
	if srv := f.RespHeaders.Get("Server"); srv != "" && strings.ContainsAny(srv, "0123456789") {
		out = append(out, Finding{Severity: Info, Check: "server-version",
			Title: "Server version disclosure", Evidence: "Server: " + srv,
			Detail: "The Server header reveals software and version information useful to an attacker.",
			Key: "server-version|" + f.Host})
	}
	if xp := f.RespHeaders.Get("X-Powered-By"); xp != "" {
		out = append(out, Finding{Severity: Info, Check: "x-powered-by",
			Title: "Technology disclosure (X-Powered-By)", Evidence: "X-Powered-By: " + xp,
			Detail: "The X-Powered-By header discloses backend technology.",
			Key: "x-powered-by|" + f.Host})
	}
	return out
}

var mixedRe = regexp.MustCompile(`(?i)(?:src|href|action)\s*=\s*["']http://[^"']+`)

func checkMixedContent(f *model.Flow) []Finding {
	if f.Scheme != "https" || !isHTML(f) {
		return nil
	}
	body := decodeResponseBody(f)
	if body == nil {
		return nil
	}
	m := mixedRe.Find(body)
	if m == nil {
		return nil
	}
	return one(Medium, "mixed-content", "Mixed content (HTTP resource on HTTPS page)",
		"The HTTPS page references at least one resource over plain HTTP, which browsers may block or which weakens page integrity.",
		string(m), "mixed-content|"+f.URL)
}

// decodeResponseBody returns the response body, decompressing gzip/deflate.
// Returns nil if the body is empty or uses an unsupported encoding (e.g. br).
func decodeResponseBody(f *model.Flow) []byte {
	if len(f.RespBody) == 0 {
		return nil
	}
	switch strings.ToLower(f.RespHeaders.Get("Content-Encoding")) {
	case "", "identity":
		return f.RespBody
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(f.RespBody))
		if err != nil {
			return nil
		}
		defer r.Close()
		b, _ := io.ReadAll(io.LimitReader(r, 8<<20))
		return b
	case "deflate":
		r := flate.NewReader(bytes.NewReader(f.RespBody))
		defer r.Close()
		b, _ := io.ReadAll(io.LimitReader(r, 8<<20))
		return b
	default:
		return nil // unsupported (e.g. brotli)
	}
}

// SeverityRank orders severities for sorting (lower is more severe).
func SeverityRank(sev string) int {
	switch sev {
	case High:
		return 0
	case Medium:
		return 1
	case Low:
		return 2
	default:
		return 3
	}
}
