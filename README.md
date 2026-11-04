# Interlace

**A web application security testing toolkit** — an intercepting proxy and
vulnerability scanner in a single Go binary. Interlace combines manual testing
tools (proxy, repeater, fuzzer) with automated passive and active scanning, and
serves its entire UI from a browser — no JVM, no external services.

> For **authorized** security testing only. Active scanning sends attack
> traffic and will only run against hosts you explicitly add to scope.

## Features

**Manual tools**
- Intercepting **proxy** for HTTP, HTTPS (MITM with its own CA) and **WebSocket**
- **Interception** of requests, responses and WebSocket frames (pause / edit / drop)
- **Repeater** (HTTP and WebSocket) and an Intruder-style **Fuzzer**
  (sniper / pitchfork / cluster-bomb, payload processing, grep-match/extract)
- **Target** site map, **Match & Replace**, **Decoder**, **Comparer**, **JWT** editor/attacker

**Automation**
- **Passive scanner** — security headers, cookie flags, CORS, mixed content,
  exposed secrets (API keys, tokens, private keys), weak JWTs
- **Active scanner** — SQL injection (error / boolean / time-based), XSS, SSTI,
  path traversal, command injection, open redirect, blind SSRF (out-of-band)
- **Crawler**, **content discovery**, **parameter mining**
- **Scope** guardrail (fail-closed), authenticated sessions, **login macros**,
  recurring **scheduled** scans

**Output**
- Printable **HTML report**, plus **JSON** and **SARIF** (for CI / GitHub code scanning)
- Extensible **JSON plugin** checks (drop files into `<data>/rules/`)

## Quick start

```sh
go build -ldflags "-s -w" -o bin/interlace ./cmd/interlace
./bin/interlace            # opens http://127.0.0.1:8081 in your browser
```

1. Install the root CA (UI → **Download CA**) into your trust store.
2. Point your browser's HTTP/HTTPS proxy at `127.0.0.1:8080`.
3. Add target hosts under **Scope** before any active scan.

A prebuilt Windows package and an Inno Setup installer script are under
`release/` and `installer/`.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md). Source is organized under `internal/`
(one package per capability) with `cmd/interlace` as the entrypoint. Run the
tests with:

```sh
go test ./...
```

## License

Proprietary — © Abinesh Kamal K U.
