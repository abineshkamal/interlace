// Command testserver is a deliberately vulnerable local target used to validate
// Interlace's active scanner. It is NOT part of the product and must only ever
// be run locally. Each endpoint simulates one vulnerability class.
package main

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // TOTP is defined on HMAC-SHA1
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

var wsUpgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

func main() {
	mux := http.NewServeMux()

	// Index page linking to the other endpoints (for crawler testing).
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h1>Test Site</h1><ul>
<li><a href="/xss?q=hi">xss</a></li>
<li><a href="/sqli?id=1">sqli</a></li>
<li><a href="/ssti?name=x">ssti</a></li>
<li><a href="/file?file=a.txt">file</a></li>
<li><a href="/ping?host=localhost">ping</a></li>
<li><a href="/safe?x=1">safe</a></li>
<li><a href="/errorpage">errorpage</a></li>
<li><a href="/listing">listing</a></li>
<li><a href="/methods">methods</a></li>
</ul></body></html>`)
	})
	// Verbose error page (triggers passive error-disclosure).
	mux.HandleFunc("/errorpage", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><b>Fatal error</b>: Uncaught Exception in /var/www/html/app.php:42
Stack trace: #0 /var/www/html/index.php(10): handler()</body></html>`)
	})
	// Directory listing page (triggers passive directory-listing).
	mux.HandleFunc("/listing", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Index of /backup</title></head><body><h1>Index of /backup</h1>
<pre><a href="db.sql">db.sql</a>  <a href="app.zip">app.zip</a></pre></body></html>`)
	})
	// Endpoint that permits TRACE (XST) and advertises risky methods via OPTIONS.
	mux.HandleFunc("/methods", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodOptions:
			w.Header().Set("Allow", "GET, POST, PUT, DELETE, TRACE")
			w.WriteHeader(http.StatusOK)
		case "TRACE":
			w.Header().Set("Content-Type", "message/http")
			fmt.Fprintf(w, "TRACE /methods HTTP/1.1\r\nHost: %s\r\nX-Interlace-XST: %s\r\n", r.Host, r.Header.Get("X-Interlace-XST"))
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html>methods demo</html>")
		}
	})

	// Reflected XSS: reflects q into HTML without encoding.
	mux.HandleFunc("/xss", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>Hello %s</body></html>", r.URL.Query().Get("q"))
	})

	// SQL injection: error-based (quote), time-based (SLEEP), boolean-based (1=1 vs 1=2).
	mux.HandleFunc("/sqli", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		up := strings.ToUpper(id)
		if strings.Contains(up, "SLEEP(5)") || strings.Contains(up, "PG_SLEEP(5)") || strings.Contains(up, "WAITFOR DELAY") {
			time.Sleep(5 * time.Second)
			fmt.Fprint(w, "ok")
			return
		}
		if strings.Contains(id, "1=1") {
			fmt.Fprint(w, "Results: Alice, Bob, Carol, Dave, Eve (5 rows matched your query)")
			return
		}
		if strings.Contains(id, "1=2") {
			fmt.Fprint(w, "Results: (no rows)")
			return
		}
		if strings.ContainsAny(id, "'\"") {
			fmt.Fprint(w, "Database error: You have an error in your SQL syntax near '"+id+"' at line 1 (MySQL)")
			return
		}
		fmt.Fprintf(w, "user %s ok", id)
	})

	// Open redirect: redirects to the url parameter verbatim.
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("url"), http.StatusFound)
	})

	// SSTI: "evaluates" the arithmetic 1338*1337 if present.
	mux.HandleFunc("/ssti", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		name = strings.NewReplacer(
			"{{1338*1337}}", "1788906", "${1338*1337}", "1788906", "#{1338*1337}", "1788906",
		).Replace(name)
		fmt.Fprintf(w, "<html>Welcome %s</html>", name)
	})

	// Path traversal: returns a fake /etc/passwd when the path escapes.
	mux.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		f := r.URL.Query().Get("file")
		if strings.Contains(f, "etc/passwd") || strings.Contains(f, "etc%2fpasswd") {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
			return
		}
		fmt.Fprint(w, "file not found")
	})

	// Command injection: echoes id output when a command separator is present.
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if strings.ContainsAny(host, ";|&`$") && strings.Contains(host, "id") {
			fmt.Fprint(w, "PING "+host+"\nuid=0(root) gid=0(root) groups=0(root)\n")
			return
		}
		fmt.Fprintf(w, "PING %s: 64 bytes\n", host)
	})

	// SSRF (non-blind): fetches the url param and echoes the body back.
	mux.HandleFunc("/proxy", func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("url")
		if strings.HasPrefix(u, "file:///etc/passwd") {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\n")
			return
		}
		fmt.Fprintf(w, "fetched %s", u)
	})

	// XXE: naively expands external entities (simulated) in an XML body.
	mux.HandleFunc("/xml", func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		body := string(buf[:n])
		if strings.Contains(body, "file:///etc/passwd") {
			fmt.Fprint(w, "<result>root:x:0:0:root:/root:/bin/bash</result>")
			return
		}
		fmt.Fprint(w, "<result>ok</result>")
	})

	// Prototype pollution (simulated): echoes a polluted global property back.
	mux.HandleFunc("/merge", func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		body := string(buf[:n])
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(body, "ILXPP1337") {
			fmt.Fprint(w, `{"ok":true,"ilxPolluted":"ILXPP1337"}`) // leaked polluted prop
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	})

	// Blind SSRF: fetches the url parameter server-side (no response echoed).
	mux.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		if u := r.URL.Query().Get("url"); u != "" {
			go func() {
				client := http.Client{Timeout: 3 * time.Second}
				if resp, err := client.Get(u); err == nil {
					resp.Body.Close()
				}
			}()
		}
		fmt.Fprint(w, "fetching in background")
	})

	// WebSocket echo endpoint (to verify WS proxying/logging).
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			mt, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			_ = c.WriteMessage(mt, append([]byte("echo: "), msg...))
		}
	})

	// Echoes request headers (to verify match-and-replace request rules).
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		for name, vals := range r.Header {
			for _, v := range vals {
				fmt.Fprintf(w, "%s: %s\n", name, v)
			}
		}
	})

	// BROKEN access control: returns admin data regardless of identity.
	mux.HandleFunc("/admin/data", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ADMIN DATA: users=[alice,bob], revenue=$1,200,000, api_key=live_xxx")
	})
	// ENFORCED access control: requires a valid admin cookie, else 403.
	mux.HandleFunc("/admin/secure", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("role"); err != nil || c.Value != "admin" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "403 Forbidden: admin only")
			return
		}
		fmt.Fprint(w, "SECURE ADMIN DATA: secret settings")
	})

	// Cookie-based SQLi (to verify cookie insertion points).
	mux.HandleFunc("/cvuln", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sid"); err == nil && strings.ContainsAny(c.Value, "'\"") {
			fmt.Fprint(w, "SQL syntax error near '"+c.Value+"' (MySQL)")
			return
		}
		fmt.Fprint(w, "ok")
	})

	// Hidden parameter: behaves differently when "debug" is supplied (for Param Miner).
	mux.HandleFunc("/hidden", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("debug") != "" {
			fmt.Fprint(w, "normal output\nDEBUG: internal state dump: user=admin, role=root, config=/etc/app.conf")
			return
		}
		fmt.Fprint(w, "normal output")
	})

	// Login endpoint that sets a session cookie (for login-macro testing).
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "authed-xyz-789", Path: "/"})
		fmt.Fprint(w, "logged in")
	})

	// Leaks secrets + a JWT (for passive secret/JWT detection).
	mux.HandleFunc("/leak", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
  "aws_key": "AKIAIOSFODNN7EXAMPLE",
  "github_token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
  "jwt": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
}`)
	})

	// Insecure deserialization.
	mux.HandleFunc("/deser", func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		b := string(buf[:n])
		if strings.Contains(b, "rO0AB") || strings.Contains(b, "O:8:") {
			fmt.Fprint(w, "java.io.InvalidClassException: bad descriptor (ObjectInputStream)")
			return
		}
		fmt.Fprint(w, "ok")
	})
	// Host header injection (reflects Host).
	mux.HandleFunc("/hostcheck", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html>Reset link: https://%s/reset</html>", r.Host)
	})
	// Cache poisoning (reflects X-Forwarded-Host in a cacheable response).
	mux.HandleFunc("/cache", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		fmt.Fprintf(w, "<link href=\"https://%s/app.js\">", r.Header.Get("X-Forwarded-Host"))
	})

	// GraphQL with introspection enabled.
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		if strings.Contains(string(buf[:n]), "__schema") {
			fmt.Fprint(w, `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User"}]}}}`)
			return
		}
		fmt.Fprint(w, `{"data":{}}`)
	})
	// NoSQL injection.
	mux.HandleFunc("/nosql", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "||") || strings.Contains(q, "$ne") || strings.Contains(q, "$gt") {
			fmt.Fprint(w, "MongoError: unexpected token in query filter")
			return
		}
		fmt.Fprint(w, "ok")
	})
	// LDAP injection.
	mux.HandleFunc("/ldap", func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("u")
		if strings.Contains(u, ")(") || strings.Contains(u, "*)") {
			fmt.Fprint(w, "javax.naming.directory: LDAPException Bad search filter")
			return
		}
		fmt.Fprint(w, "ok")
	})
	// CRLF / header injection (simulated: reflects an injected header).
	mux.HandleFunc("/crlf", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("x"), "X-Interlace-CRLF") {
			w.Header().Set("X-Interlace-CRLF", "injected")
		}
		fmt.Fprint(w, "ok")
	})

	// Mock OpenAI-compatible Chat Completions endpoint (to test AI provider-agnostic path).
	mux.HandleFunc("/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		reqBody, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		content := `## Assessment\n- Likely a **true positive**.\n- Impact: data exposure.\n- Remediation: validate input and enforce authorization.`
		body := string(reqBody)
		switch {
		case strings.Contains(body, "BUSINESS LOGIC"):
			// Business Logic Advisor: return a JSON array of test-case objects.
			content = `[{\"title\":\"IDOR on account view\",\"category\":\"idor\",\"severity\":\"high\",\"endpoint\":\"GET /account\",\"rationale\":\"Account appears tied to the session; test fetching another user's account.\",\"mutation\":\"change the account id to another user's\",\"steps\":\"request /account with a different id; if another balance returns, IDOR confirmed\"},{\"title\":\"Mass assignment of role\",\"category\":\"privilege-escalation\",\"severity\":\"high\",\"endpoint\":\"POST /massassign\",\"rationale\":\"Endpoint binds the whole body; adding role/isAdmin may escalate.\",\"mutation\":\"add \\\"isAdmin\\\":true to the JSON body\",\"steps\":\"submit with isAdmin true and check if it is accepted\"}]`
		case strings.Contains(body, "JSON array"):
			// Natural-language scope: return a JSON array of matching URLs.
			content = `[\"http://127.0.0.1:9000/login\", \"http://127.0.0.1:9000/admin/data\"]`
		}
		fmt.Fprintf(w, `{"choices":[{"message":{"role":"assistant","content":"%s"}}]}`, content)
	})

	// A clean endpoint (no issues) to confirm the scanner doesn't false-positive.
	mux.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html>ok</html>")
	})

	// Login form + handler + protected page (for testing scripted form login).
	mux.HandleFunc("/loginform", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><form action="/dologin" method="post">
<input type="hidden" name="csrf" value="tok123">
<input type="text" name="uid" placeholder="user">
<input type="password" name="passw" placeholder="pass">
<button type="submit">Sign in</button></form></body></html>`)
	})
	mux.HandleFunc("/dologin", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		w.Header().Set("Content-Type", "text/html")
		if r.FormValue("uid") == "admin" && r.FormValue("passw") == "admin" {
			http.SetCookie(w, &http.Cookie{Name: "authsess", Value: "ok-admin-1", Path: "/"})
			// Real apps redirect the login POST to a GET-able landing page.
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		fmt.Fprint(w, `<html><body>Invalid. <input type="password" name="passw"></body></html>`)
	})
	// --- 2-step MFA (TOTP) login flow, for testing authenticated scans ---
	const mfaSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	mux.HandleFunc("/mfaform", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><form action="/mfalogin" method="post">
<input name="uid"><input type="password" name="passw"><button>Sign in</button></form></body></html>`)
	})
	mux.HandleFunc("/mfalogin", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		w.Header().Set("Content-Type", "text/html")
		if r.FormValue("uid") == "admin" && r.FormValue("passw") == "admin" {
			// Step 2: ask for the one-time code.
			fmt.Fprint(w, `<html><body>Enter your authentication code
<form action="/mfaverify" method="post"><input type="hidden" name="csrf" value="z1">
<input type="text" name="otp" autocomplete="one-time-code"><button>Verify</button></form></body></html>`)
			return
		}
		fmt.Fprint(w, `<html><body>Invalid. <input type="password" name="passw"></body></html>`)
	})
	mux.HandleFunc("/mfaverify", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.FormValue("otp") == totp(mfaSecret, time.Now()) {
			http.SetCookie(w, &http.Cookie{Name: "authsess", Value: "ok-admin-1", Path: "/"})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>Bad code. <input type="text" name="otp"></body></html>`)
	})

	// Authenticated landing page (GET-able) linking to the protected area, so an
	// authenticated crawl seeded from the login redirect discovers post-login pages.
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if c, err := r.Cookie("authsess"); err == nil && c.Value == "ok-admin-1" {
			fmt.Fprint(w, `<html><body><h1>Dashboard</h1>Welcome, admin.
<ul><li><a href="/account">My account</a></li>
<li><a href="/transfer?to=2&amount=100">Transfer</a></li>
<li><a href="/massassign">Edit profile</a></li></ul></body></html>`)
			return
		}
		fmt.Fprint(w, "<html>Please log in.</html>")
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("authsess"); err == nil && c.Value == "ok-admin-1" {
			fmt.Fprint(w, "<html>Account balance: $4,200.00 (acct #8842)</html>")
			return
		}
		fmt.Fprint(w, "<html>Please log in.</html>")
	})
	mux.HandleFunc("/transfer", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("authsess"); err == nil && c.Value == "ok-admin-1" {
			fmt.Fprintf(w, "<html>Transferred %s to account %s</html>", r.URL.Query().Get("amount"), r.URL.Query().Get("to"))
			return
		}
		fmt.Fprint(w, "<html>Please log in.</html>")
	})

	// CSRF token page: returns an anti-CSRF token in the body (for testing the
	// session CSRF auto-refresh feature).
	mux.HandleFunc("/csrftoken", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<form><input type="hidden" name="csrf_token" value="CSRF-TKN-55aa"></form>`)
	})

	// Proxied endpoint: emits a Via header to simulate sitting behind a front-end
	// proxy (used to exercise the request-smuggling gate).
	mux.HandleFunc("/proxied", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Via", "1.1 interlace-demo-proxy")
		fmt.Fprint(w, "behind a proxy\n")
	})

	// Mass assignment: naively binds the whole JSON body into a user object and
	// echoes it back, so any extra fields (role, isAdmin, …) are reflected.
	mux.HandleFunc("/massassign", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]any
		if json.Unmarshal(body, &m) != nil {
			m = map[string]any{}
		}
		out, _ := json.Marshal(map[string]any{"updated": true, "user": m})
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	})

	fmt.Println("vulnerable test server on http://127.0.0.1:9000")
	_ = http.ListenAndServe("127.0.0.1:9000", mux)
}

// totp computes an RFC 6238 6-digit TOTP (SHA-1, 30s) for a base32 secret.
func totp(secret string, t time.Time) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return ""
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(t.Unix())/30)
	m := hmac.New(sha1.New, key)
	m.Write(buf)
	s := m.Sum(nil)
	o := s[len(s)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(s[o:o+4])&0x7fffffff)%1000000)
}
