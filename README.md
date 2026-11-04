# Interlace

**A web application security testing toolkit** — an intercepting proxy and
vulnerability scanner in a single Go binary. Interlace combines manual testing
tools (proxy, repeater, fuzzer) with automated passive and active scanning, and
serves its entire UI from a browser — no JVM, no external services.

> For **authorized** security testing only. Active scanning sends attack
> traffic and will only run against hosts you explicitly add to scope.

## Features

**Manual tools**
- Intercepting **proxy** for HTTP, HTTPS (MITM with its own CA), **HTTP/2** (to
  the client over ALPN, with HTTP/1.1 fallback) and **WebSocket**
- **Interception** of requests, responses and WebSocket frames (pause / edit / drop)
- **Repeater** (HTTP and WebSocket) and an Intruder-style **Fuzzer**
  (sniper / pitchfork / cluster-bomb, payload processing, grep-match/extract)
- **Target** site map, **Match & Replace**, **Decoder**, **Comparer**, **JWT** editor/attacker

**Automation**
- **Passive scanner** — security headers, cookie flags, CORS, mixed content,
  exposed secrets (API keys, tokens, private keys), weak JWTs
- **Active scanner** — SQL injection (error / boolean / time-based), XSS, SSTI,
  path traversal, command injection, open redirect, XXE, SSRF, prototype
  pollution, NoSQL / LDAP / CRLF injection, insecure deserialization,
  host-header injection, web cache poisoning, **HTTP request smuggling**
  (CL.TE / TE.CL timing), blind SSRF (out-of-band), GraphQL introspection
- **Crawler**, **content discovery**, **parameter mining**
- **Scope** guardrail (fail-closed), authenticated sessions, **login macros**,
  recurring **scheduled** scans

**Output**
- Printable **HTML report**, plus **JSON** and **SARIF** (for CI / GitHub code scanning)
- Extensible **JSON plugin** checks (drop files into `<data>/rules/`)

## Quick start (UI)

```sh
go build -ldflags "-s -w" -o bin/interlace ./cmd/interlace
./bin/interlace            # opens http://127.0.0.1:8081 in your browser
```

1. Install the root CA (UI → **Download CA**) into your trust store.
2. Point your browser's HTTP/HTTPS proxy at `127.0.0.1:8080`.
3. Add target hosts under **Scope** before any active scan.

A prebuilt Windows package and an Inno Setup installer script are under
`release/` and `installer/`.

## Headless / CI scanning

Run a one-shot crawl + active scan and emit a report (SARIF for GitHub code
scanning, or JSON). Exit code is non-zero when findings meet `--fail-on`.

```sh
interlace scan https://target.example --out report.sarif --format sarif --fail-on high
```

Docker:

```sh
docker build -t interlace .
docker run --rm interlace scan https://target.example --fail-on high
```

A ready-to-use GitHub Action is in `.github/workflows/security-scan.yml`.

## AI-assisted triage (optional, provider-agnostic)

In the UI → **AI**, choose a provider (**Anthropic** or **OpenAI-compatible** —
OpenAI, Azure, Gemini, Groq, OpenRouter, or a **local** Ollama/LM Studio/vLLM
endpoint via a base URL) and add a key. Then **🤖 Analyze with AI** on any
finding, or **✨ AI** in the Fuzzer to generate payloads. Keys are stored
locally and sent only to the endpoint you configure.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md). Source is organized under `internal/`
(one package per capability) with `cmd/interlace` as the entrypoint. Run the
tests with:

```sh
go test ./...
```

## License

Proprietary — © Abinesh Kamal K U.
