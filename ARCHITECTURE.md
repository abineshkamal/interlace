# Interlace — Architecture

Interlace is a web application security testing toolkit (an intercepting proxy
plus scanners) built as a single Go binary that serves a browser UI. It has no
JVM, no external services, and stores each project in one SQLite file.

## Processes & ports

A single `interlace.exe` runs three listeners:

| Port (default) | Purpose |
|---|---|
| `127.0.0.1:8080` | Intercepting **proxy** (HTTP/HTTPS/WebSocket MITM) |
| `127.0.0.1:8081` | **UI + JSON API** (embedded web app, served via `go:embed`) |
| `127.0.0.1:8082` | **Out-of-band** interaction listener (blind-vuln callbacks) |

The UI is a single self-contained `index.html` embedded in the binary. It talks
to the API over `fetch` and receives live updates over Server-Sent Events (SSE).
Because it is a web app, multiple browsers can watch the same live session.

## Request lifecycle (proxy)

```
client ──▶ proxy :8080
             │  CONNECT? ─ peek first byte ─ 0x16 → TLS MITM (per-host leaf cert from internal/ca)
             │                               else → plaintext tunnel (e.g. ws://)
             │  Upgrade: websocket? → internal/proxy/websocket.go (frame relay + intercept)
             ▼
        forward() in internal/proxy/proxy.go
             ├─ request interception (hold/edit/drop)      [internal/intercept]
             ├─ match-and-replace on request                [internal/matchreplace]
             ├─ RoundTrip to upstream
             ├─ match-and-replace on response
             ├─ response interception (hold/edit/drop)
             └─ OnFlow(flow) ─▶ processFlow()
                                  ├─ store flow            [internal/store → SQLite]
                                  ├─ broadcast to UI (SSE) [internal/hub]
                                  └─ passive scan          [internal/scanner.Scan]
```

## Packages (`internal/`)

| Package | Responsibility |
|---|---|
| `ca` | Root CA generation + per-host leaf certificate minting (cached) |
| `proxy` | MITM proxy, HTTP/1.1 + WebSocket; interception & match-replace hooks |
| `store` | SQLite persistence (flows, findings, ws_messages) — pure-Go driver |
| `hub` | SSE pub/sub broadcaster (flows, findings, OOB, intercept events) |
| `model` | Shared data types (`Flow`, `WSMessage`) |
| `scanner` | Passive checks (`passive.go`) + active engine (`active.go`, JSON rules) |
| `scope` | Fail-closed host allow/deny rules — gates all active actions |
| `repeater` | Hand-edited request sender (also used by the scanner & fuzzer) |
| `fuzzer` | Intruder-style attacks (sniper/pitchfork/clusterbomb), grep/extract |
| `recon` | Content discovery + parameter mining |
| `crawler` | Same-origin link crawl feeding history + passive scan |
| `oob` | Out-of-band interaction server (blind SSRF/RCE) |
| `intercept` / `wsintercept` | Pause/edit/drop HTTP requests+responses / WS frames |
| `matchreplace` | Regex rewrite rules for proxied traffic |
| `session` | Auth headers attached to repeater/scanner/crawl requests |
| `macro` | Login-sequence record + replay (captures session cookies) |
| `scheduler` | Recurring batch scans |
| `recon` | Content discovery + parameter mining |
| `ai` | Optional AI triage/payloads — provider-agnostic (Anthropic or OpenAI-compatible) |
| `notify` | Webhook notifications (Slack/Discord/generic) on findings |

## Scanner model

- **Passive** checks (`scanner.Scan`) never send requests; they inspect captured
  flows and emit deduplicated `Finding`s (dedup key per check+host).
- **Active** checks (`scanner.RunActive`) send probe requests through
  `repeater.Sender`. Rules are JSON (`rules/active.json`, embedded + user files
  from `<data>/rules/`). Rule types: `grep`, `header-grep`, `reflection`,
  `redirect`, `oob`, `time`, `boolean`, plus special checks (XXE, prototype
  pollution, GraphQL). Insertion points: query, form body, cookie, JSON body.
- **Headless mode:** `interlace scan <url>` crawls + active-scans and writes a
  SARIF/JSON report with CI exit codes (`cmd/interlace` → `runScanCLI`).
- **Scope is enforced** before any active scan, fuzz, crawl, discovery or
  param-mine: out-of-scope hosts are refused (fail-closed).

## Data & distribution

- One SQLite DB per project in the `-data` directory, plus JSON config files
  (scope, session, match-replace, schedule, macro) and the CA.
- Ships as a portable zip or an Inno Setup installer (`installer/interlace.iss`).

## Testing

`go test ./...` covers scope rules, fuzzer attack generation, passive checks,
active-scan parsing/insertion points, and match-replace. The `testserver/`
command is a deliberately vulnerable local target used for end-to-end checks;
`wsclient/` drives a WebSocket through the proxy.

## Build

Requires the Go toolchain only (CGO disabled — pure-Go deps). On the dev machine
all caches are redirected to `E:` (see the project memory) because `C:` is full.

```
go build -ldflags "-s -w" -o bin/interlace.exe ./cmd/interlace
```
