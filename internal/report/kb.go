package report

import (
	"fmt"
	"regexp"
	"strings"
)

var evidenceParamRe = regexp.MustCompile(`param "([^"]+)" \(([^)]+)\)`)

// paramPhrase turns scanner evidence like `param "q" (query)` into a readable
// clause such as `the "q" query-string parameter`, or "" if none is present.
func paramPhrase(evidence string) string {
	m := evidenceParamRe.FindStringSubmatch(evidence)
	if m == nil {
		return ""
	}
	loc := map[string]string{
		"query": "query-string", "body": "request-body", "cookie": "cookie",
		"header": "header", "json": "JSON-body", "path": "URL-path",
	}[m[2]]
	if loc == "" {
		loc = m[2]
	}
	return fmt.Sprintf("the “%s” %s parameter", m[1], loc)
}

// Meta is the remediation knowledge for a finding type: what it means for the
// business, how to fix it, standard references (CWE / OWASP Top 10), and a
// representative CVSS v3.1 base score for the weakness class.
type Meta struct {
	Observation string // narrative clause following "It was observed that the application [at URL] …"
	Impact      string
	Remediation string
	CWE         string  // e.g. "CWE-79"
	CWEName     string  // e.g. "Improper Neutralization of Input During Web Page Generation"
	OWASP       string  // e.g. "A03:2021 – Injection"
	CVSS        float64 // CVSS v3.1 base score (0 = informational / not scored)
	CVSSVector  string  // CVSS v3.1 base vector (without the "CVSS:3.1/" prefix)
}

// ObservationText composes a professional observation sentence for a report,
// weaving in the affected URL and, where the evidence identifies it, the
// specific parameter (e.g. the "q" query-string parameter).
func (m Meta) ObservationText(url, detail, evidence string) string {
	lead := "It was observed that the application"
	if url != "" {
		lead += " at " + url
	}
	if m.Observation != "" {
		obs := m.Observation
		if pp := paramPhrase(evidence); pp != "" {
			obs = strings.Replace(obs, "the affected parameter", pp, 1)
		}
		return lead + " " + obs
	}
	if detail != "" {
		return lead + " is affected by this issue: " + strings.TrimSpace(detail)
	}
	return lead + " is affected by this issue."
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
	case "missing-hsts", "cookie-no-secure", "password-over-http":
		return 5.9, "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
	case "graphql-introspection", "cookie-no-httponly", "error-disclosure", "directory-listing", "http-trace", "http-methods":
		return 5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
	case "missing-csp", "missing-xfo":
		return 4.3, "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
	case "missing-nosniff", "missing-referrer-policy", "private-ip-disclosure":
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
		Observation: "accepts user-supplied input in the affected parameter and reflects it into the HTTP response without adequate input validation or output encoding. A crafted script payload was returned unencoded and executed in the browser, confirming a Reflected Cross-Site Scripting (XSS) vulnerability.",
		Impact:      "An attacker can run arbitrary JavaScript in victims' browsers, leading to session/cookie theft, account takeover, credential harvesting, and defacement.",
		Remediation: "It is recommended to validate all user input against a strict allow-list and to apply context-aware output encoding to every piece of user-controllable data rendered in a response (HTML, attribute, JavaScript and URL contexts). In addition, deploy a strong Content-Security-Policy header with restrictive directives (for example, default-src 'self'; script-src 'self'; object-src 'none') to limit script execution, and set the HttpOnly, Secure and SameSite attributes on session cookies to reduce the impact of any residual cross-site scripting.",
		CWE:         "CWE-79", CWEName: "Cross-site Scripting", OWASP: "A03:2021 – Injection",
	},
	"sqli-error": sqli, "sqli-time": sqli, "sqli-boolean": sqli,
	"ssti": {
		Observation: "evaluates user-supplied input within a server-side template engine. A template expression injected in the affected parameter was evaluated by the server, confirming a Server-Side Template Injection vulnerability that commonly leads to remote code execution.",
		Impact:      "Server-side template injection commonly escalates to remote code execution on the application server, exposing data and the host.",
		Remediation: "It is recommended to never pass user-supplied input into template engines as part of the template itself. User data should be provided strictly as bound variables to a pre-defined template. Where dynamic templates are unavoidable, use a sandboxed, logic-less templating engine and apply strict input validation.",
		CWE:         "CWE-1336", CWEName: "Server-Side Template Injection", OWASP: "A03:2021 – Injection",
	},
	"path-traversal": {
		Observation: "uses user-supplied input to construct a file path without adequate canonicalisation or validation. Directory-traversal sequences supplied in the affected parameter allowed access to files outside the intended directory, confirming a Path Traversal vulnerability.",
		Impact:      "An attacker can read files outside the intended directory — source code, configuration and secrets — and sometimes write/overwrite files.",
		Remediation: "It is recommended to avoid building file paths directly from user input. Where a file must be selected by the user, map the input to a fixed allow-list of permitted files, canonicalise the resolved path and verify it remains within the intended base directory before access. Run the application with least-privilege file-system permissions.",
		CWE:         "CWE-22", CWEName: "Path Traversal", OWASP: "A01:2021 – Broken Access Control",
	},
	"cmdi": {
		Observation: "passes user-supplied input to an operating-system command without adequate sanitisation. Command-separator metacharacters injected in the affected parameter were executed by the server, confirming an OS Command Injection vulnerability.",
		Impact:      "OS command injection gives the attacker arbitrary command execution on the server, typically resulting in full host compromise.",
		Remediation: "It is recommended to avoid invoking operating-system commands with user-supplied input. Where a system call is unavoidable, use native language APIs instead of a shell, pass arguments as a parameter array (never a concatenated command string), and validate input against a strict allow-list. Run the process with least privilege.",
		CWE:         "CWE-78", CWEName: "OS Command Injection", OWASP: "A03:2021 – Injection",
	},
	"open-redirect": {
		Observation: "uses a user-controllable parameter as the target of an HTTP redirect without validating it against trusted destinations, allowing the application to redirect users to an arbitrary external site.",
		Impact:      "A trusted domain can be used to redirect users to attacker sites for phishing and credential theft, and to bypass redirect-based protections.",
		Remediation: "It is recommended to validate redirect targets against an allow-list of permitted internal paths, or to use indirect references (a mapping of identifiers to URLs) rather than accepting a user-supplied absolute URL. Where external redirects are required, display an interstitial warning page.",
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
		Observation: "binds request parameters directly to internal object properties, and accepted additional attacker-supplied fields that were not part of the intended request. This confirms a mass-assignment (auto-binding) weakness that can be used to set privileged attributes.",
		Impact:      "Binding attacker-supplied fields the server did not intend (e.g. role, isAdmin, balance) can escalate privileges or tamper with records.",
		Remediation: "It is recommended to bind only an explicit allow-list of permitted fields per endpoint (for example, using data-transfer objects or a 'fillable' allow-list), and to never bind the full request body directly to the data model. Sensitive attributes such as role, permissions and identifiers should only be settable by trusted server-side logic.",
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
		Observation: "does not return a Strict-Transport-Security response header over HTTPS, so browsers are not instructed to enforce HTTPS for subsequent requests.",
		Impact:      "Without HSTS, users can be downgraded to HTTP and have traffic intercepted or modified (man-in-the-middle).",
		Remediation: "It is recommended to add the Strict-Transport-Security header with a long max-age (for example, 31536000 seconds) and the includeSubDomains directive, and to consider HSTS preloading once the policy has been validated across all subdomains.",
		CWE:         "CWE-319", CWEName: "Cleartext Transmission of Sensitive Information", OWASP: "A05:2021 – Security Misconfiguration",
	},
	"missing-csp": {
		Observation: "does not return a Content-Security-Policy response header, so the browser is not provided with a policy restricting the sources from which scripts, styles and other content may be loaded.",
		Impact:      "Absent CSP removes a key defence-in-depth control against cross-site scripting and data injection.",
		Remediation: "It is recommended to implement a strong Content-Security-Policy header with restrictive directives — for example, default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none' — avoiding 'unsafe-inline' and 'unsafe-eval'. Roll the policy out in report-only mode first to tune it before enforcing.",
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
		Observation: "sets a session cookie without the Secure attribute, so the cookie may be transmitted over an unencrypted HTTP connection.",
		Impact:      "A session cookie without Secure can be transmitted over HTTP and captured by a network attacker.",
		Remediation: "It is recommended to set the Secure attribute on all session and authentication cookies so that they are only ever sent over HTTPS, and to enforce HTTPS site-wide together with HSTS.",
		CWE:         "CWE-614", CWEName: "Sensitive Cookie Without 'Secure' Attribute", OWASP: "A05:2021 – Security Misconfiguration",
	},
	"cookie-no-httponly": {
		Observation: "sets a session cookie without the HttpOnly attribute, making the cookie accessible to client-side JavaScript.",
		Impact:      "A cookie without HttpOnly is readable by JavaScript, so an XSS flaw can steal the session.",
		Remediation: "It is recommended to set the HttpOnly attribute on all session and authentication cookies so that they cannot be read by JavaScript, limiting the impact of any cross-site scripting flaw.",
		CWE:         "CWE-1004", CWEName: "Sensitive Cookie Without 'HttpOnly' Flag", OWASP: "A05:2021 – Security Misconfiguration",
	},
	"cookie-no-samesite": {
		Observation: "sets a session cookie without an appropriate SameSite attribute, so the cookie is sent on cross-site requests.",
		Impact:      "A cookie without SameSite is sent on cross-site requests, enabling cross-site request forgery.",
		Remediation: "It is recommended to set the SameSite attribute (Lax or Strict) on session and authentication cookies to prevent them from being sent on cross-site requests, and to implement anti-CSRF tokens on state-changing operations.",
		CWE:         "CWE-1275", CWEName: "Sensitive Cookie with Improper SameSite Attribute", OWASP: "A05:2021 – Security Misconfiguration",
	},
	"error-disclosure": {
		Observation: "returns verbose error output — a stack trace, debug page or raw database error — directly to the client, disclosing internal file paths, library versions and application logic.",
		Impact:      "Verbose errors and stack traces reveal internal file paths, library versions, SQL and application logic that help an attacker craft targeted attacks.",
		Remediation: "It is recommended to return a generic error page to end users while logging the full error details server-side only, and to disable debug/development mode in production environments.",
		CWE:         "CWE-209", CWEName: "Generation of Error Message Containing Sensitive Information", OWASP: "A05:2021 – Security Misconfiguration",
	},
	"directory-listing": {
		Observation: "returns an automatic directory listing for a requested path, exposing the names of files and folders that should not be enumerable.",
		Impact:      "An automatic directory listing exposes file and folder names — backups, source and configuration files — that should not be enumerable.",
		Remediation: "It is recommended to disable automatic directory listing (autoindex) on the web server, ensure a default document is present in each directory, and remove backup, source and configuration files from web-accessible locations.",
		CWE:         "CWE-548", CWEName: "Exposure of Information Through Directory Listing", OWASP: "A05:2021 – Security Misconfiguration",
	},
	"password-over-http": {
		Impact:      "A password field delivered over cleartext HTTP lets a network attacker capture credentials in transit or tamper with the login form.",
		Remediation: "Serve all authentication pages and form submissions exclusively over HTTPS and enable HSTS.",
		CWE:         "CWE-319", CWEName: "Cleartext Transmission of Sensitive Information", OWASP: "A02:2021 – Cryptographic Failures",
	},
	"http-trace": {
		Impact:      "With TRACE enabled, Cross-Site Tracing can read headers (including auth cookies) that HttpOnly and other protections would normally hide.",
		Remediation: "Disable the TRACE (and TRACK) method at the web server/application tier.",
		CWE:         "CWE-693", CWEName: "Protection Mechanism Failure", OWASP: "A05:2021 – Security Misconfiguration",
	},
	"http-methods": {
		Impact:      "Dangerous HTTP methods (PUT/DELETE/CONNECT/…) may allow uploading, modifying or deleting content or proxying requests if not strictly controlled.",
		Remediation: "Disable unused HTTP methods and enforce method-level authorization on every endpoint.",
		CWE:         "CWE-650", CWEName: "Trusting HTTP Permission Methods on the Server Side", OWASP: "A05:2021 – Security Misconfiguration",
	},
	"private-ip-disclosure": {
		Impact:      "Internal IP addresses or hostnames in responses reveal network topology that aids lateral movement and internal targeting.",
		Remediation: "Remove internal addresses and hostnames from responses, error messages and headers.",
		CWE:         "CWE-200", CWEName: "Exposure of Sensitive Information", OWASP: "A05:2021 – Security Misconfiguration",
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
		Observation: "incorporates user-supplied input directly into back-end SQL queries without proper parameterisation. Specially crafted input supplied in the affected parameter altered the intended query logic, confirming a SQL Injection vulnerability.",
		Impact:      "SQL injection can read, modify or delete any data in the database, bypass authentication, and in some configurations execute commands on the database host.",
		Remediation: "It is recommended to use parameterised queries (prepared statements) for every database interaction so that user input is always treated as data and never as query structure. Where an ORM or stored procedures are used, ensure they are not concatenating input internally. Additionally, apply strict server-side input validation, enforce least-privilege database accounts, and return generic error messages so that database errors are not disclosed to the client.",
		CWE:         "CWE-89", CWEName: "SQL Injection", OWASP: "A03:2021 – Injection",
	}
	ssrf = Meta{
		Observation: "makes server-side requests to a destination derived from user-controllable input without adequate validation, allowing the request to be redirected to arbitrary hosts. This confirms a Server-Side Request Forgery (SSRF) vulnerability.",
		Impact:      "Server-side request forgery lets an attacker reach internal services and cloud metadata endpoints, often disclosing credentials and enabling further compromise.",
		Remediation: "It is recommended to validate and allow-list the permitted outbound destinations (scheme, host and port) rather than accepting arbitrary user-supplied URLs. Explicitly block requests to internal/private IP ranges, link-local cloud-metadata addresses (169.254.169.254) and non-HTTP schemes such as file://. Disable unnecessary URL redirection following, and segment the application network so that back-end services are not reachable from the application tier.",
		CWE:         "CWE-918", CWEName: "Server-Side Request Forgery (SSRF)", OWASP: "A10:2021 – Server-Side Request Forgery",
	}
	cors = Meta{
		Observation: "returns a permissive Cross-Origin Resource Sharing (CORS) policy that reflects or wildcards the requesting origin, allowing untrusted web origins to read authenticated responses from this application.",
		Impact:      "A permissive cross-origin policy can let untrusted sites read responses from this origin, exposing user or application data.",
		Remediation: "It is recommended to restrict the Access-Control-Allow-Origin header to a maintained allow-list of trusted origins and to never reflect an arbitrary or 'null' origin. Do not combine a wildcard or reflected origin with Access-Control-Allow-Credentials. Return CORS headers only on endpoints that genuinely require cross-origin access.",
		CWE:         "CWE-942", CWEName: "Permissive Cross-domain Policy with Untrusted Domains", OWASP: "A05:2021 – Security Misconfiguration",
	}
	infoLeak = Meta{
		Observation: "discloses its underlying software and version information through response headers, assisting an attacker in fingerprinting the technology stack.",
		Impact:      "Technology/version disclosure helps an attacker fingerprint the stack and target known vulnerabilities.",
		Remediation: "It is recommended to remove or obfuscate version and technology headers (such as Server and X-Powered-By) at the web server or application tier, so that software versions are not exposed to clients.",
		CWE:         "CWE-200", CWEName: "Exposure of Sensitive Information", OWASP: "A05:2021 – Security Misconfiguration",
	}
)
