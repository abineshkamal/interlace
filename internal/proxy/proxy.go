// Package proxy implements Interlace's intercepting HTTP/HTTPS proxy.
//
// Plain HTTP requests arrive as absolute-URI proxy requests and are forwarded
// directly. HTTPS is intercepted via the CONNECT method: the proxy hijacks the
// client connection, completes a TLS handshake using a per-host leaf
// certificate signed by the Interlace root CA, then reads, captures and
// forwards the decrypted requests.
package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"interlace/internal/ca"
	"interlace/internal/model"
)

// hopByHop headers must not be forwarded between client and upstream.
var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// maxBodyCapture caps how much of a body we buffer for storage (16 MiB).
const maxBodyCapture = 16 << 20

// Interceptor optionally pauses requests for manual edit/drop before they are
// forwarded. It may be nil.
type Interceptor interface {
	Enabled() bool
	Hold(scheme, host, method, url, raw string) (editedRaw string, drop bool)
	RespEnabled() bool
	HoldResponse(scheme, host, method, url string, status int, raw string) (editedRaw string, drop bool)
}

// WSInterceptor optionally pauses WebSocket messages for edit/drop. May be nil.
type WSInterceptor interface {
	Enabled() bool
	HoldWS(host, url, dir, opcode, payload string) (editedPayload string, drop bool)
}

// Rewriter optionally applies match-and-replace rules to traffic. It may be nil.
type Rewriter interface {
	Enabled() bool
	ApplyRequestLine(host, method, path string) (string, string)
	ApplyHeaders(part, host string, h http.Header)
	ApplyBody(part, host string, body []byte) []byte
}

// Options configures a Proxy.
type Options struct {
	Addr             string            // listen address, e.g. "127.0.0.1:8080"
	CA               *ca.CA            // certificate authority for MITM
	OnFlow           func(*model.Flow)      // called for every captured flow (may be nil)
	OnWS             func(*model.WSMessage) // called for every WebSocket message (may be nil)
	InsecureUpstream bool                   // accept invalid upstream TLS certs (common for testing targets)
	Interceptor      Interceptor       // optional request interception
	WSInterceptor    WSInterceptor     // optional WebSocket message interception
	Rewriter         Rewriter          // optional match-and-replace
}

// Proxy is an intercepting HTTP/HTTPS proxy.
type Proxy struct {
	opts      Options
	transport *http.Transport
}

// New builds a Proxy from opts.
func New(opts Options) *Proxy {
	tr := &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.InsecureUpstream, //nolint:gosec // intentional for a testing proxy
		},
	}
	return &Proxy{opts: opts, transport: tr}
}

// ListenAndServe starts the proxy and blocks until it fails.
func (p *Proxy) ListenAndServe() error {
	srv := &http.Server{
		Addr:    p.opts.Addr,
		Handler: http.HandlerFunc(p.handle),
		// Disable HTTP/2 on the client-facing listener; we speak HTTP/1.1 to
		// clients for now (simpler and universally supported).
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	log.Printf("Interlace proxy listening on http://%s", p.opts.Addr)
	return srv.ListenAndServe()
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handlePlain(w, r)
}

// handlePlain forwards a plain-HTTP proxy request and captures it.
func (p *Proxy) handlePlain(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		http.Error(w, "Interlace: expected absolute-URI proxy request", http.StatusBadRequest)
		return
	}
	if isWebSocket(r.Header) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Interlace: hijacking not supported", http.StatusInternalServerError)
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		p.handleWebSocket(conn, brw.Reader, r.Method, r.URL.RequestURI(), r.Header, "ws", r.URL.Host)
		return
	}
	resp, body, flow := p.forward(r, "http")
	if resp == nil {
		http.Error(w, "Interlace upstream error: "+flow.Error, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers (minus hop-by-hop) to the client. Content-Length is
	// dropped so the server recomputes it (match-and-replace may have resized
	// the body).
	for _, h := range hopByHop {
		resp.Header.Del(h)
	}
	resp.Header.Del("Content-Length")
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

// handleConnect establishes a MITM TLS tunnel for an HTTPS target.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	authority := r.Host // e.g. "example.com:443"
	hostname := stripPort(authority)

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Interlace: hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		log.Printf("hijack %s: %v", authority, err)
		return
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// Peek the first byte to tell TLS (0x16 = TLS handshake record) from a
	// plaintext tunnel (e.g. ws:// that a client sent via CONNECT).
	br := bufio.NewReader(clientConn)
	peek, _ := br.Peek(1)
	bc := &bufferedConn{Conn: clientConn, r: br}

	if len(peek) > 0 && peek[0] == 0x16 {
		tlsConf := &tls.Config{
			NextProtos: []string{"http/1.1"},
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				name := hello.ServerName
				if name == "" {
					name = hostname
				}
				return p.opts.CA.CertForHost(name)
			},
		}
		tlsConn := tls.Server(bc, tlsConf)
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("tls handshake %s: %v", authority, err)
			return
		}
		p.serveTunnel(tlsConn, bufio.NewReader(tlsConn), authority, "https", "wss")
		return
	}
	// Plaintext tunnel (ws:// or plain HTTP sent over CONNECT).
	p.serveTunnel(bc, br, authority, "http", "ws")
}

// serveTunnel reads HTTP/1.1 requests off a (decrypted or plaintext) tunnel,
// forwards each upstream, captures it, and writes the response back. WebSocket
// upgrades are handed to handleWebSocket. It loops to honor keep-alive.
func (p *Proxy) serveTunnel(conn net.Conn, br *bufio.Reader, authority, scheme, wsScheme string) {
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if isWebSocket(req.Header) {
			p.handleWebSocket(conn, br, req.Method, req.URL.RequestURI(), req.Header, wsScheme, authority)
			return
		}

		req.URL.Scheme = scheme
		req.URL.Host = authority
		req.RequestURI = ""

		resp, body, _ := p.forward(req, scheme)
		if resp == nil {
			io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			return
		}

		keepAlive := writeResponse(conn, resp, body)
		resp.Body.Close()
		if !keepAlive || req.Close {
			return
		}
	}
}

// bufferedConn is a net.Conn whose reads are served from a bufio.Reader that has
// already peeked/buffered some bytes from the underlying connection.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// forward issues req upstream, buffers the response body, records a Flow via
// OnFlow, and returns the response (with a re-readable body), the buffered body
// bytes, and the Flow. On error it returns (nil, nil, flow-with-error).
func (p *Proxy) forward(req *http.Request, scheme string) (*http.Response, []byte, *model.Flow) {
	start := time.Now()

	reqBody := readCapped(req.Body)
	if req.Body != nil {
		req.Body.Close()
	}

	// Interception: optionally pause the request for manual edit/drop.
	if p.opts.Interceptor != nil && p.opts.Interceptor.Enabled() {
		raw := buildRawRequest(req, reqBody)
		edited, drop := p.opts.Interceptor.Hold(scheme, stripPort(req.URL.Host), req.Method, req.URL.String(), raw)
		if drop {
			flow := &model.Flow{Timestamp: start, Method: req.Method, Scheme: scheme,
				Host: stripPort(req.URL.Host), Path: req.URL.RequestURI(), URL: req.URL.String(),
				ReqHeaders: cloneHeader(req.Header), ReqBody: reqBody, Error: "dropped by user",
				DurationMs: time.Since(start).Milliseconds()}
			p.emit(flow)
			return nil, nil, flow
		}
		if edited != raw {
			applyEditedRaw(req, edited, &reqBody)
		}
	}

	// Match-and-replace on the outgoing request.
	if p.opts.Rewriter != nil && p.opts.Rewriter.Enabled() {
		host := stripPort(req.URL.Host)
		m, pth := p.opts.Rewriter.ApplyRequestLine(host, req.Method, req.URL.RequestURI())
		req.Method = m
		if u, err := url.Parse(pth); err == nil {
			req.URL.Path = u.Path
			req.URL.RawQuery = u.RawQuery
		}
		p.opts.Rewriter.ApplyHeaders("req-header", host, req.Header)
		reqBody = p.opts.Rewriter.ApplyBody("req-body", host, reqBody)
	}

	flow := &model.Flow{
		Timestamp:  start,
		Method:     req.Method,
		Scheme:     scheme,
		Host:       stripPort(req.URL.Host),
		Path:       req.URL.RequestURI(),
		URL:        req.URL.String(),
		ReqHeaders: cloneHeader(req.Header),
		ReqBody:    reqBody,
	}

	outReq, err := http.NewRequest(req.Method, req.URL.String(), bytes.NewReader(reqBody))
	if err != nil {
		flow.Error = err.Error()
		p.emit(flow)
		return nil, nil, flow
	}
	copyHeader(outReq.Header, req.Header)
	for _, h := range hopByHop {
		outReq.Header.Del(h)
	}

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		flow.Error = err.Error()
		flow.DurationMs = time.Since(start).Milliseconds()
		p.emit(flow)
		return nil, nil, flow
	}

	respBody := readCapped(resp.Body)
	resp.Body.Close()

	// Match-and-replace on the response.
	if p.opts.Rewriter != nil && p.opts.Rewriter.Enabled() {
		host := stripPort(req.URL.Host)
		p.opts.Rewriter.ApplyHeaders("resp-header", host, resp.Header)
		respBody = p.opts.Rewriter.ApplyBody("resp-body", host, respBody)
	}

	// Response interception: optionally pause the response for edit/drop.
	if p.opts.Interceptor != nil && p.opts.Interceptor.RespEnabled() {
		rawResp := buildRawResponse(resp, respBody)
		edited, drop := p.opts.Interceptor.HoldResponse(scheme, stripPort(req.URL.Host), req.Method, req.URL.String(), resp.StatusCode, rawResp)
		if drop {
			flow.Error = "response dropped by user"
			flow.DurationMs = time.Since(start).Milliseconds()
			p.emit(flow)
			return nil, nil, flow
		}
		if edited != rawResp {
			applyEditedResponse(resp, edited, &respBody)
		}
	}

	flow.StatusCode = resp.StatusCode
	flow.RespHeaders = cloneHeader(resp.Header)
	flow.RespBody = respBody
	flow.ContentType = resp.Header.Get("Content-Type")
	flow.DurationMs = time.Since(start).Milliseconds()
	p.emit(flow)

	// Make the body re-readable for the caller.
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	return resp, respBody, flow
}

func (p *Proxy) emit(f *model.Flow) {
	if p.opts.OnFlow != nil {
		p.opts.OnFlow(f)
	}
}

// writeResponse writes resp (with buffered body) to a raw connection and
// reports whether the connection may be kept alive.
func writeResponse(conn net.Conn, resp *http.Response, body []byte) bool {
	for _, h := range hopByHop {
		resp.Header.Del(h)
	}
	// We buffered the full body, so send it with an explicit length.
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.TransferEncoding = nil
	resp.Header.Del("Content-Length")

	keepAlive := !resp.Close && resp.ProtoAtLeast(1, 1)
	if keepAlive {
		resp.Header.Set("Connection", "keep-alive")
	} else {
		resp.Header.Set("Connection", "close")
	}
	if err := resp.Write(conn); err != nil {
		return false
	}
	return keepAlive
}

func readCapped(r io.Reader) []byte {
	if r == nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(r, maxBodyCapture))
	return b
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vv := range h {
		out[k] = append([]string(nil), vv...)
	}
	return out
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// buildRawRequest renders a request as raw HTTP/1.1 text for interception.
func buildRawRequest(req *http.Request, body []byte) string {
	var b strings.Builder
	b.WriteString(req.Method + " " + req.URL.RequestURI() + " HTTP/1.1\r\n")
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	b.WriteString("Host: " + host + "\r\n")
	for name, vals := range req.Header {
		if strings.EqualFold(name, "Host") {
			continue
		}
		for _, v := range vals {
			b.WriteString(name + ": " + v + "\r\n")
		}
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.String()
}

// buildRawResponse renders a response as raw HTTP/1.1 text for interception.
func buildRawResponse(resp *http.Response, body []byte) string {
	var b strings.Builder
	b.WriteString(resp.Proto + " " + resp.Status + "\r\n")
	for name, vals := range resp.Header {
		if strings.EqualFold(name, "Content-Length") {
			continue
		}
		for _, v := range vals {
			b.WriteString(name + ": " + v + "\r\n")
		}
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.String()
}

// applyEditedResponse parses an edited raw response and updates resp and body.
func applyEditedResponse(resp *http.Response, raw string, body *[]byte) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	head, bodyPart := raw, ""
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		head, bodyPart = raw[:i], raw[i+2:]
	}
	lines := strings.Split(head, "\n")
	if len(lines) > 0 {
		parts := strings.SplitN(strings.TrimSpace(lines[0]), " ", 2)
		if len(parts) == 2 {
			if code := atoiSafe(strings.Fields(parts[1])[0]); code > 0 {
				resp.StatusCode = code
				resp.Status = parts[1]
			}
		}
	}
	newHeader := http.Header{}
	for _, ln := range lines[1:] {
		c := strings.IndexByte(ln, ':')
		if c < 0 {
			continue
		}
		newHeader.Add(strings.TrimSpace(ln[:c]), strings.TrimSpace(ln[c+1:]))
	}
	resp.Header = newHeader
	*body = []byte(bodyPart)
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// applyEditedRaw parses an edited raw request and updates req and body in place.
func applyEditedRaw(req *http.Request, raw string, body *[]byte) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	head, bodyPart := raw, ""
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		head, bodyPart = raw[:i], raw[i+2:]
	}
	lines := strings.Split(head, "\n")
	if len(lines) == 0 {
		return
	}
	parts := strings.Fields(strings.TrimSpace(lines[0]))
	if len(parts) >= 2 {
		req.Method = parts[0]
		if u, err := url.Parse(parts[1]); err == nil {
			req.URL.Path = u.Path
			req.URL.RawQuery = u.RawQuery
		}
	}
	newHeader := http.Header{}
	for _, ln := range lines[1:] {
		c := strings.IndexByte(ln, ':')
		if c < 0 {
			continue
		}
		name := strings.TrimSpace(ln[:c])
		val := strings.TrimSpace(ln[c+1:])
		if strings.EqualFold(name, "Host") {
			req.Host = val
			continue
		}
		newHeader.Add(name, val)
	}
	req.Header = newHeader
	*body = []byte(bodyPart)
}
