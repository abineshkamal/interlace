# Interlace Roadmap

Status of features and what's planned. ✅ done · 🟡 planned · 🔴 heavy / long-term.

## Done

**Core proxy & manual tools**
- ✅ Intercepting proxy: HTTP, HTTPS (MITM CA), WebSocket
- ✅ Interception of requests, responses and WebSocket frames (pause/edit/drop)
- ✅ Repeater (HTTP + WebSocket), Intruder-style Fuzzer (sniper/pitchfork/cluster-bomb, payload processing, grep-match/extract, **AI-generated payloads**)
- ✅ Target site map, Match & Replace, Decoder, Comparer, JWT editor/attacker
- ✅ Full-text search across captured traffic

**Automation & scanning**
- ✅ Passive scanner: security headers, cookies, CORS (+reflection/null-origin), mixed content, cacheable-sensitive, **exposed secrets**, **weak JWTs**, **technology fingerprinting**
- ✅ Active scanner: SQLi (error/boolean/time), XSS, SSTI, path traversal, command injection, open redirect, **XXE**, **SSRF**, **prototype pollution**, **NoSQL**, **LDAP**, **CRLF/header injection**, blind SSRF (OOB), **GraphQL introspection**
- ✅ Insertion points: query, form body, cookies, JSON body
- ✅ Crawler, content discovery, parameter mining
- ✅ Scope guardrail (fail-closed), authenticated sessions, login macros, scheduled scans
- ✅ **Authorization testing** (Autorize-style broken-access-control / IDOR)

**Integration & output**
- ✅ HTML / JSON / **SARIF** reports (grouped by host, remediation guidance)
- ✅ **Headless CLI scan mode** (`interlace scan <url>`) with exit codes
- ✅ **Docker image** + **GitHub Action** (SARIF → code scanning)
- ✅ **Webhook notifications** (Slack/Discord/generic) on findings
- ✅ **AI-assisted triage**, **provider-agnostic** (Anthropic or any OpenAI-compatible / local model)
- ✅ Extensible JSON plugin checks (`<data>/rules/`)

## Planned

- 🟡 OpenAPI / Swagger / Postman import to seed scan targets
- 🟡 Session handling: auto-refresh CSRF tokens, per-host session rules
- 🟡 Project export/import (single portable file), multi-project switching
- 🟡 AI executive summary on reports; AI natural-language scope
- 🟡 UI access token, save/load Fuzzer/Repeater sessions, light/dark toggle
- 🟡 More checks: insecure deserialization, host-header injection, web cache poisoning

## Long-term

- 🔴 Headless-browser crawling (SPA support + DOM-based XSS)
- 🔴 HTTP/2 to the client; HTTP request smuggling detection
- 🔴 DNS-based out-of-band (requires a public domain)
- 🔴 Real-time multi-user collaboration (shared session, comments)

Contributions and check-rule PRs welcome.
