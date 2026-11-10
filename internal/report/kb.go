package report

import (
	"fmt"
	"strings"
)

// Meta is the remediation knowledge for a finding type: what it means for the
// business, how to fix it, standard references (CWE / OWASP Top 10), and a
// representative CVSS v3.1 base score for the weakness class.
type Meta struct {
	Impact      string
	Remediation string
	CWE         string  // e.g. "CWE-79"
	CWEName     string  // e.g. "Improper Neutralization of Input During Web Page Generation"
	OWASP       string  // e.g. "A03:2021 – Injection"
	CVSS        float64 // CVSS v3.1 base score (0 = informational / not scored)
	CVSSVector  string  // CVSS v3.1 base vector (without the "CVSS:3.1/" prefix)
}

// CVSSRating maps the base score to its qualitative severity band.
func (m Meta) CVSSRating() string {
	switch {
	case m.CVSS >= 9.0:
		return "Critical"
	case m.CVSS >= 7.0:
		return "High"
	case m.CVSS >= 4.0:
		return "Medium"
	case m.CVSS > 0:
		return "Low"
	default:
		return "None"
	}
}

// CVSSText renders the score for a report, e.g. "7.5 (High) — CVSS:3.1/AV:N/…".
func (m Meta) CVSSText() string {
	if m.CVSS <= 0 {
		return "N/A (informational)"
	}
	return fmt.Sprintf("%.1f (%s) — CVSS:3.1/%s", m.CVSS, m.CVSSRating(), m.CVSSVector)
}

// cvssFor returns a representative CVSS v3.1 base score + vector for a check.
func cvssFor(check string) (float64, string) {
	switch check {
	case "sqli-error", "sqli-time", "sqli-boolean", "nosqli", "ssti", "cmdi", "insecure-deser", "jwt-alg-none":
		return 9.8, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	case "ssrf", "blind-ssrf":
		return 8.6, "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
	case "mass-assignment", "broken-access-control":
		return 8.1, "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
	case "path-traversal", "xxe", "exposed-secret", "cors-wildcard-credentials":
		return 7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
	case "proto-pollution", "ldapi":
		return 7.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
	case "http-request-smuggling", "cache-poisoning":
		return 7.5, "AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:N"
	case "cors-wildcard", "cors-origin-reflection", "cors-null-origin":
		return 6.5, "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
	case "reflected-xss", "open-redirect", "crlf", "host-header-injection", "cookie-no-samesite":
		return 6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
	case "missing-hsts", "cookie-no-secure":
		return 5.9, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
	case "graphql-introspection", "cookie-no-httponly":
		return 5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
	case "missing-csp", "missing-xfo":
		return 4.3, "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
	case "missing-nosniff", "missing-referrer-policy":
		return 3.7, "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
	default: // server-version, x-powered-by, jwt-observed, graphql-endpoint, unknown → informational
		return 0, ""
	}
}

// CWEURL returns the MITRE reference URL for the finding's CWE, or "".
func (m Meta) CWEURL() string {
	if m.CWE == "" {
		return ""
	}
	return "https://cwe.mitre.org/data/definitions/" + strings.TrimPrefix(m.CWE, "CWE-") + ".html"
}

// Reference returns a human-readable references line (CWE + OWASP).
func (m Meta) Reference() string {
	var parts []string
	if m.CWE != "" {
		ref := m.CWE
		if m.CWEName != "" {
			ref += " (" + m.CWEName + ")"
		}
		parts = append(parts, ref)
	}
	if m.OWASP != "" {
		parts = append(parts, "OWASP "+m.OWASP)
	}
	return strings.Join(parts, " · ")
}

// MetaFor returns the knowledge-base entry for a scanner check slug. Unknown
// checks get a generic entry so the report is always complete.
func MetaFor(check string) Meta {
	m, ok := kb[check]
	if !ok {
		m = Meta{
			Impact:      "May weaken the security posture of the application; review in context to determine exploitability and business impact.",
			Remediation: "Review the affected request/response and apply the appropriate hardening for this issue class.",
		}
	}
	m.CVSS, m.CVSSVector = cvssFor(check)
	return m
}

// kb maps every scanner check slug to its remediation knowledge.
var kb = map[string]Meta{
	// ---- Injection (active) ----
	"reflected-xss": {
		Impact:      "An attacker can run arbitrary JavaScript in victims' browsers, leading to session/cookie theft, account takeover, credential harvesting, and defacement.",
		Remediation: "Context-encode all output, validate input, and apply a strict Content-Security-Policy. Prefer framework auto-escaping.",
		CWE:         "CWE-79", CWEName: "Cross-site Scripting", OWASP: "A03:2021 – Injection",
	},
	"sqli-error":   sqli, "sqli-time": sqli, "sqli-boolean": sqli,
	"ssti": {
		Impact:      "Server-side template injection commonly escalates to remote code execution on the application server, exposing data and the host.",
		Remediation: "Never pass user input into template engines. Use logic-less templates or a sandbox, and pass data as bound variables.",
		CWE:         "CWE-1336", CWEName: "Server-Side Template Injection", OWASP: "A03:2021 – Injection",
	},
	"path-traversal": {
		Impact:      "An attacker can read files outside the intended directory — source code, configuration and secrets — and sometimes write/overwrite files.",
		Remediation: "Canonicalize and validate paths against an allowlist; never build file paths from user input. Use safe file APIs.",
		CWE:         "CWE-22", CWEName: "Path Traversal", OWASP: "A01:2021 – Broken Access Control",
	},
	"cmdi": {
		Impact:      "OS command injection gives the attacker arbitrary command execution on the server, typically resulting in full host compromise.",
		Remediation: "Avoid shelling out with user input. Use native APIs, pass arguments as a list (no shell), and apply strict allowlists.",
		CWE:         "CWE-78", CWEName: "OS Command Injection", OWASP: "A03:2021 – Injection",
	},
	"open-redirect": {
		Impact:      "A trusted domain can be used to redirect users to attacker sites for phishing and credential theft, and to bypass redirect-based protections.",
		Remediation: "Validate redirect targets against an allowlist of internal paths; do not redirect to user-controlled absolute URLs.",
		CWE:         "CWE-601", CWEName: "Open Redirect", OWASP: "A01:2021 – Broken Access Control",
	},
	"ssrf": ssrf, "blind-ssrf": ssrf,
	"xxe": {
		Impact:      "XML external entity processing allows local file disclosure, server-side request forgery, and denial of service.",
		Remediation: "Disable external entity and DTD processing in the XML parser; prefer less complex data formats where possible.",
		CWE:         "CWE-611", CWEName: "XML External Entity Reference", OWASP: "A05:2021 – Security Misconfiguration",
	},
	"proto-pollution": {
		Impact:      "Prototype pollution can corrupt application objects, causing denial of service, security-control bypass and, in some stacks, remote code execution.",
		Remediation: "Reject __proto__/constructor/prototype keys, avoid recursive merges of untrusted input, and use null-prototype objects or Map.",
		CWE:         "CWE-1321", CWEName: "Prototype Pollution", OWASP: "A08:2021 – Software and Data Integrity Failures",
	},
	"nosqli": {
		Impact:      "NoSQL injection can bypass authentication and read or modify database records.",
		Remediation: "Validate and type-check input; use the driver's typed query builder and never pass raw operators from user input.",
		CWE:         "CWE-943", CWEName: "Improper Neutralization of Data Within Query Logic", OWASP: "A03:2021 – Injection",
	},
	"ldapi": {
		Impact:      "LDAP injection can bypass authentication and disclose or modify directory data.",
		Remediation: "Escape LDAP filter metacharacters and use parameterized directory queries.",
		CWE:         "CWE-90", CWEName: "LDAP Injection", OWASP: "A03:2021 – Injection",
	},
	"crlf": {
		Impact:      "CR/LF injection enables HTTP response splitting and header injection, leading to cache poisoning, XSS and request smuggling.",
		Remediation: "Reject CR/LF in values used to build headers; use the framework's header API, which encodes them.",
		CWE:         "CWE-113", CWEName: "HTTP Response Splitting", OWASP: "A03:2021 – Injection",
	},
	"insecure-deser": {
		Impact:      "Deserializing untrusted data can lead to remote code execution, privilege escalation and data tampering.",
		Remediation: "Never deserialize untrusted input. Use data-only formats (JSON) and signed/allowlisted deserialization.",
		CWE:         "CWE-502", CWEName: "Deserialization of Untrusted Data", OWASP: "A08:2021 – Software and Data Integrity Failures",
	},
	"mass-assignment": {
		Impact:      "Binding attacker-supplied fields the server did not intend (e.g. role, isAdmin, balance) can escalate privileges or tamper with records.",
		Remediation: "Bind only an explicit allowlist of fields per endpoint; never bind the full request object to the model.",
		CWE:         "CWE-915", CWEName: "Improperly Controlled Modification of Object Attributes (Mass Assignment)", OWASP: "A08:2021 – Software and Data Integrity Failures",
	},
	"http-request-smuggling": {
		Impact:      "Request smuggling lets an attacker poison the cache, hijack other users' requests, and bypass front-end security controls.",
		Remediation: "Use a single consistent parser front-to-back; reject ambiguous Content-Length/Transfer-Encoding and normalize at the edge.",
		CWE:         "CWE-444", CWEName: "HTTP Request/Response Smuggling", OWASP: "A05:2021 – Security Misconfiguration",
	},
	"host-header-injection": {
		Impact:      "A trusted Host value can poison password-reset links and the web cache, and can drive server-side request forgery.",
		Remediation: "Validate the Host header against an allowlist; build absolute URLs from configuration, not the request Host.",
		CWE:         "CWE-644", CWEName: "Improper Neutralization of HTTP Headers", OWASP: "A05:2021 – Security Misconfiguration",
	},
	"cache-poisoning": {
		Impact:      "A poisoned cache can serve attacker-controlled or stale content to many users from a trusted origin.",
		Remediation: "Include all request inputs that affect the response in the cache key, or mark such responses uncacheable.",
		CWE:         "CWE-525", CWEName: "Information Exposure Through Browser Caching", OWASP: "A05:2021 – Security Misconfiguration",
	},
	// ---- Secrets / disclosure ----
	"exposed-secret": {
		Impact:      "A leaked credential or key can be used directly to compromise accounts, data or infrastructure.",
		Remediation: "Rotate the exposed credential immediately and remove secrets from responses, source and logs; store them in a secrets manager.",
		CWE:         "CWE-312", CWEName: "Cleartext Storage of Sensitive Information", OWASP: "A02:2021 – Cryptographic Failures",
	},
	"server-version": infoLeak, "x-powered-by": infoLeak,
	"graphql-introspection": {
		Impact:      "An exposed GraphQL schema reveals types, fields and operations that help an attacker map and target the API.",
		Remediation: "Disable introspection in production and apply per-field authorization plus query depth/complexity limits.",
		CWE:         "CWE-200", CWEName: "Exposure of Sensitive Information", OWASP: "A05:2021 – Security Misconfiguration",
	},
	"graphql-endpoint": {
		Impact:      "Informational — a GraphQL endpoint was identified; review its exposure and authorization.",
		Remediation: "Ensure authorization is enforced per field and introspection is disabled in production.",
		CWE:         "CWE-200", CWEName: "Exposure of Sensitive Information", OWASP: "A05:2021 – Security Misconfiguration",
	},
	// ---- JWT ----
	"jwt-alg-none": {
		Impact:      "Accepting the \"none\" algorithm lets an attacker forge tokens and bypass authentication entirely.",
		Remediation: "Reject \"none\"; pin and verify the expected algorithm and verify signatures with a strong key/secret.",
		CWE:         "CWE-347", CWEName: "Improper Verification of Cryptographic Signature", OWASP: "A02:2021 – Cryptographic Failures",
	},
	"jwt-observed": {
		Impact:      "Informational — a JSON Web Token was observed; review its algorithm, claims and expiry.",
		Remediation: "Verify signatures, pin the algorithm, use short expiries and keep secrets out of the token payload.",
		CWE:         "CWE-522", CWEName: "Insufficiently Protected Credentials", OWASP: "A02:2021 – Cryptographic Failures",
	},
	// ---- Access control ----
	"broken-access-control": {
		Impact:      "Missing authorization lets a user access other users' data or privileged functions (IDOR / privilege escalation).",
		Remediation: "Enforce server-side authorization on every request; verify the current user owns or may access the referenced object.",
		CWE:         "CWE-639", CWEName: "Authorization Bypass Through User-Controlled Key (IDOR)", OWASP: "A01:2021 – Broken Access Control",
	},
	// ---- Transport / headers ----
	"missing-hsts": {
		Impact:      "Without HSTS, users can be downgraded to HTTP and have traffic intercepted or modified (man-in-the-middle).",
		Remediation: "Add Strict-Transport-Security with a long max-age and includeSubDomains (consider preload).",
		CWE:         "CWE-319", CWEName: "Cleartext Transmission of Sensitive Information", OWASP: "A05:2021 – Security Misconfiguration",
	},
	"missing-csp": {
		Impact:      "Absent CSP removes a key defence-in-depth control against cross-site scripting and data injection.",
		Remediation: "Define a Content-Security-Policy restricting script/style/frame sources; avoid unsafe-inline.",
		CWE:         "CWE-693", CWEName: "Protection Mechanism Failure", OWASP: "A05:2021 – Security Misconfiguration",
	},
	"missing-xfo": {
		Impact:      "Without frame protection the page can be embedded by an attacker and used for clickjacking.",
		Remediation: "Set X-Frame-Options: DENY or a Content-Security-Policy frame-ancestors directive.",
		CWE:         "CWE-1021", CWEName: "Improper Restriction of Rendered UI Layers (Clickjacking)", OWASP: "A05:2021 – Security Misconfiguration",
	},
	"missing-nosniff": {
		Impact:      "MIME-sniffing can cause the browser to execute responses as an unintended type, enabling XSS.",
		Remediation: "Add X-Content-Type-Options: nosniff and serve correct Content-Type headers.",
		CWE:         "CWE-16", CWEName: "Configuration", OWASP: "A05:2021 – Security Misconfiguration",
	},
	"missing-referrer-policy": {
		Impact:      "Without a Referrer-Policy, full URLs (which may contain tokens or IDs) can leak to third-party sites.",
		Remediation: "Set Referrer-Policy (e.g. strict-origin-when-cross-origin).",
		CWE:         "CWE-200", CWEName: "Exposure of Sensitive Information", OWASP: "A05:2021 – Security Misconfiguration",
	},
	"cookie-no-secure": {
		Impact:      "A session cookie without Secure can be transmitted over HTTP and captured by a network attacker.",
		Remediation: "Set the Secure attribute on all session/auth cookies.",
		CWE:         "CWE-614", CWEName: "Sensitive Cookie Without 'Secure' Attribute", OWASP: "A05:2021 – Security Misconfiguration",
	},
	"cookie-no-httponly": {
		Impact:      "A cookie without HttpOnly is readable by JavaScript, so an XSS flaw can steal the session.",
		Remediation: "Set the HttpOnly attribute on session/auth cookies.",
		CWE:         "CWE-1004", CWEName: "Sensitive Cookie Without 'HttpOnly' Flag", OWASP: "A05:2021 – Security Misconfiguration",
	},
	"cookie-no-samesite": {
		Impact:      "A cookie without SameSite is sent on cross-site requests, enabling cross-site request forgery.",
		Remediation: "Set SameSite=Lax or Strict on session/auth cookies.",
		CWE:         "CWE-1275", CWEName: "Sensitive Cookie with Improper SameSite Attribute", OWASP: "A05:2021 – Security Misconfiguration",
	},
	"cors-wildcard": cors, "cors-origin-reflection": cors, "cors-null-origin": cors,
	"cors-wildcard-credentials": {
		Impact:      "Reflecting the origin together with credentials lets any site read authenticated responses, exposing user data cross-origin.",
		Remediation: "Never combine a reflected/wildcard Access-Control-Allow-Origin with Allow-Credentials; use a strict origin allowlist.",
		CWE:         "CWE-942", CWEName: "Permissive Cross-domain Policy with Untrusted Domains", OWASP: "A05:2021 – Security Misconfiguration",
	},
}

// Shared entries for check families.
var (
	sqli = Meta{
		Impact:      "SQL injection can read, modify or delete any data in the database, bypass authentication, and in some configurations execute commands on the database host.",
		Remediation: "Use parameterized queries / prepared statements for every query; never concatenate user input into SQL.",
		CWE:         "CWE-89", CWEName: "SQL Injection", OWASP: "A03:2021 – Injection",
	}
	ssrf = Meta{
		Impact:      "Server-side request forgery lets an attacker reach internal services and cloud metadata endpoints, often disclosing credentials and enabling further compromise.",
		Remediation: "Validate and allowlist outbound destinations; block internal ranges, link-local metadata IPs and file:// — do not follow attacker-controlled URLs.",
		CWE:         "CWE-918", CWEName: "Server-Side Request Forgery (SSRF)", OWASP: "A10:2021 – Server-Side Request Forgery",
	}
	cors = Meta{
		Impact:      "A permissive cross-origin policy can let untrusted sites read responses from this origin, exposing user or application data.",
		Remediation: "Restrict Access-Control-Allow-Origin to a trusted allowlist; never reflect arbitrary or null origins.",
		CWE:         "CWE-942", CWEName: "Permissive Cross-domain Policy with Untrusted Domains", OWASP: "A05:2021 – Security Misconfiguration",
	}
	infoLeak = Meta{
		Impact:      "Technology/version disclosure helps an attacker fingerprint the stack and target known vulnerabilities.",
		Remediation: "Remove or obfuscate version/technology headers (Server, X-Powered-By, etc.).",
		CWE:         "CWE-200", CWEName: "Exposure of Sensitive Information", OWASP: "A05:2021 – Security Misconfiguration",
	}
)
