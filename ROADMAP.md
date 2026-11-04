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

**Integration & output**
- ✅ HTML / JSON / **SARIF** reports (grouped by host, remediation guidance)
- ✅ **Headless CLI scan mode** (`interlace scan <url>`) with exit codes
- ✅ **Docker image** + **GitHub Action** (SARIF → code scanning)
- ✅ **Webhook notifications** (Slack/Discord/generic) on findings
- ✅ **AI-assisted triage** + **executive summary**, **provider-agnostic** (Anthropic or any OpenAI-compatible / local model), **AI-generated fuzzing payloads**
- ✅ **OpenAPI / Swagger / Postman import** to seed scan targets
- ✅ **Project export/import** (single portable JSON file)
- ✅ **Save/load Repeater requests**, **UI access token**, **save/load Fuzzer presets**, **light/dark theme toggle**
- ✅ Extensible JSON plugin checks (`<data>/rules/`)

## Planned

- 🟡 Multi-project switching in-app (today: one project per `--data` dir, moved via project export/import)
- 🟡 More checks: SSRF via DNS rebinding, more mass-assignment heuristics

## Long-term

- 🔴 Headless-browser crawling (SPA support + DOM-based XSS) — needs an embedded Chromium
- 🔴 DNS-based out-of-band (requires a public domain + DNS server)
- 🔴 Real-time multi-user collaboration (shared live session; finding notes already shared)

Contributions and check-rule PRs welcome.
