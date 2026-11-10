# Interlace Roadmap

Status of features and what's planned. ✅ done · 🟡 planned · 🔴 heavy / long-term.

## Done

**Core proxy & manual tools**
- ✅ Intercepting proxy: HTTP, HTTPS (MITM CA), **HTTP/2 to the client** (ALPN h2, falls back to HTTP/1.1), WebSocket
- ✅ Interception of requests, responses and WebSocket frames (pause/edit/drop)
- ✅ Repeater (HTTP + WebSocket), Intruder-style Fuzzer (sniper/pitchfork/cluster-bomb, payload processing, grep-match/extract, **AI-generated payloads**)
- ✅ Target site map, Match & Replace, Decoder, Comparer, JWT editor/attacker
- ✅ Full-text search across captured traffic

**Automation & scanning**
- ✅ Passive scanner: security headers, cookies, CORS (+reflection/null-origin), mixed content, cacheable-sensitive, **exposed secrets**, **weak JWTs**, **technology fingerprinting**
- ✅ Active scanner: SQLi (error/boolean/time), XSS, SSTI (**multi-engine polyglots**), path traversal, command injection, open redirect, **XXE**, **SSRF**, **prototype pollution**, **mass assignment**, **NoSQL**, **LDAP**, **CRLF/header injection**, **insecure deserialization**, **host-header injection**, **web cache poisoning**, **HTTP request smuggling (CL.TE / TE.CL, timing-based, proxy-gated)**, blind SSRF (OOB), **GraphQL introspection**
- ✅ Insertion points: query, form body, cookies, JSON body
- ✅ Crawler, content discovery, parameter mining
- ✅ Scope guardrail (fail-closed), authenticated sessions, **per-host session rules**, **CSRF token auto-refresh**, login macros, scheduled scans
- ✅ **AI natural-language target selection** ("scan all login endpoints" → picks endpoints, adds hosts to scope)
- ✅ **Authorization testing** (Autorize-style broken-access-control / IDOR), **analyst notes on findings**

**Automated pentest**
- ✅ **One-click Automated Pentest** — target URL (+ optional username/password)
  → crawl **+ form submission** → full active scan → bounded authz sweep →
  screenshot evidence → report. Scope guardrail stays fail-closed.
- ✅ **Scripted form login** (auto-detects the login form; preserves hidden/CSRF
  fields) for authenticated scanning
- ✅ **Screenshot evidence** via installed headless Edge/Chrome, stored on findings
- ✅ **Reports in HTML, PDF, Word (.docx) and Excel (.xlsx)** (all pure-Go)

**Integration & output**
- ✅ HTML / JSON / **SARIF** reports (grouped by host, remediation guidance)
- ✅ **Headless CLI scan mode** (`interlace scan <url>`) with exit codes
- ✅ **Docker image** + **GitHub Action** (SARIF → code scanning)
- ✅ **Webhook notifications** (Slack/Discord/generic) on findings
- ✅ **AI-assisted triage** + **executive summary**, **provider-agnostic** (Anthropic or any OpenAI-compatible / local model), **AI-generated fuzzing payloads**
- ✅ **Business Logic Advisor** — give the app's context + roles and the AI crafts concrete, app-specific business-logic test cases (IDOR, price tampering, workflow bypass, privilege escalation, …) from the captured endpoints, each openable in Repeater
- ✅ **Authenticated pentest** — scripted form login with optional **TOTP/2FA** (RFC 6238), seeds the crawl from the post-login landing page plus user-supplied extra entry points, and live progress with clickable crawled requests for manual testing
- ✅ **Client-ready reports** (HTML/PDF/Word/Excel) — executive summary + severity breakdown, and per-finding affected URL, description, impact, recommendation, **CVSS v3.1 score/vector** and **CWE + OWASP Top 10** references
- ✅ **Expanded detection** — verbose-error/stack-trace disclosure, directory listing, cleartext password forms, internal-IP disclosure, and Cross-Site Tracing (TRACE) / risky HTTP methods, on top of the injection + misconfiguration checks
- ✅ **OpenAPI / Swagger / Postman import** to seed scan targets
- ✅ **Project export/import** (single portable JSON file)
- ✅ **Save/load Repeater requests**, **UI access token**, **save/load Fuzzer presets**, **light/dark theme toggle**
- ✅ Extensible JSON plugin checks (`<data>/rules/`)

## Planned

- 🟡 Multi-project switching in-app (today: one project per `--data` dir, moved via project export/import)
- 🟡 More checks: SSRF via DNS rebinding, more mass-assignment heuristics

## Long-term

- 🔴 Authenticated-context screenshots + SSO/MFA login driving via the Chrome
  DevTools Protocol (v1 screenshots render in an anonymous context)
- 🔴 Headless-browser crawling (SPA support + DOM-based XSS) — builds on the CDP driver
- 🔴 DNS-based out-of-band (requires a public domain + DNS server)
- 🔴 Real-time multi-user collaboration (shared live session; finding notes already shared)

Contributions and check-rule PRs welcome.
