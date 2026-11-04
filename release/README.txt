INTERLACE  v0.1.0
Web Application Security Testing Toolkit
==========================================

Interlace is an intercepting proxy and vulnerability scanner for AUTHORIZED
web application security testing. It is a single self-contained executable.

-------------------------------------------------
QUICK START
-------------------------------------------------
1. Double-click  interlace.exe  (or run  Start-Interlace.bat).
   - The console window must stay open while you work.
   - Your browser opens automatically at  http://127.0.0.1:8081

2. Install the CA certificate (needed to intercept HTTPS):
   - In the Interlace UI, click  "Download CA"  and save the .pem file.
   - Windows: double-click it > Install Certificate > Local Machine >
     "Place all certificates in the following store" > Trusted Root
     Certification Authorities.
   - Or import it into your browser's certificate settings.

3. Point your browser (or tool) at the proxy:
   - HTTP and HTTPS proxy:  127.0.0.1 : 8080
   - Click "Setup" in the UI for step-by-step help.

4. Browse your target. Traffic appears live under "Proxy".

-------------------------------------------------
TOOLS
-------------------------------------------------
Proxy     - Live HTTP/HTTPS history with full request/response inspection.
Intercept - Toggle (top bar) to pause each request, edit the raw text, then
            Forward or Drop it.
Repeater  - Edit and resend any request; inspect the response.
Fuzzer    - Payload-based attacks (sniper / pitchfork / cluster bomb) with
            grep-match and live results.
Issues    - Passive findings (security headers, cookies, CORS, info leaks)
            detected automatically, plus active-scan results.
OOB       - Out-of-band interaction server for blind vulnerabilities; shows
            callbacks live. Active scans use it automatically for blind SSRF.
Tools     - Decoder (Base64 / URL / HTML / hex / JWT) and Comparer (text diff).
Scope     - The hosts you are allowed to actively scan or crawl.

On any captured request:
  Scan    - probes for SQL injection, XSS, SSTI, path traversal, command
            injection, open redirect and blind SSRF (out-of-band).
  Crawl   - follows same-origin links, adding pages to history and scanning
            them passively.
  Fuzzer / Repeater - send the request to those tools.

Export report - a printable HTML report of all findings (print to PDF).

Plugins   - Add your own active-scan checks as JSON (no rebuild). See the
            plugins-example folder and put rule files in  <data>\rules .

-------------------------------------------------
IMPORTANT - AUTHORIZED USE ONLY
-------------------------------------------------
Active scanning sends attack traffic. Interlace will ONLY actively scan hosts
you add under "Scope". Only test systems you own or have explicit written
permission to test. You are responsible for how you use this tool.

-------------------------------------------------
COMMAND-LINE OPTIONS
-------------------------------------------------
  interlace.exe -proxy 127.0.0.1:8080 -api 127.0.0.1:8081 -data .\data -open=true

  -proxy  address the intercepting proxy listens on   (default 127.0.0.1:8080)
  -api    address the UI / API listens on             (default 127.0.0.1:8081)
  -data   directory for the CA, project database, scope (default .\interlace-data)
  -open   open the browser on startup                 (default true)
  -insecure-upstream  accept invalid target TLS certs (default true)

Data (captured traffic, findings, CA, scope) is stored in the -data folder.
Delete it to start a clean project.
