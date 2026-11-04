// Package repeater sends a hand-edited HTTP request to a target and returns the
// response, powering Interlace's Repeater tool. Unlike the proxy, requests here
// are composed/edited by the user rather than captured.
package repeater

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// maxBody caps the response body we buffer (16 MiB).
const maxBody = 16 << 20

// Request is a Repeater send request as posted by the UI.
type Request struct {
	Scheme string `json:"scheme"` // "http" or "https"
	Host   string `json:"host"`   // target authority, may include port
	Raw    string `json:"raw"`    // raw HTTP/1.1 request text (request line + headers + body)
}

// Response is the result returned to the UI.
type Response struct {
	Status     int    `json:"status"`
	StatusText string `json:"statusText"`
	Proto      string `json:"proto"`
	Headers    string `json:"headers"` // formatted header block
	Body       string `json:"body"`    // text body (empty if binary)
	Binary     bool   `json:"binary"`
	BodyLen    int    `json:"bodyLen"`
	DurationMs int64  `json:"durationMs"`
	Error      string `json:"error,omitempty"`
}

// Applier adds configured session headers to outgoing requests (optional).
type Applier interface{ Apply(http.Header) }

// Sender issues Repeater requests over a shared transport.
type Sender struct {
	tr      *http.Transport
	session Applier
}

// SetSession attaches a session header applier used on every send.
func (s *Sender) SetSession(a Applier) { s.session = a }

// New builds a Sender. If insecure is true, invalid upstream TLS certs are
// accepted (common when testing targets with self-signed certs).
func New(insecure bool) *Sender {
	return &Sender{tr: &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec
		TLSHandshakeTimeout:   15 * time.Second,
		ForceAttemptHTTP2:     true,
		ResponseHeaderTimeout: 30 * time.Second,
	}}
}

// Send parses the raw request, issues it against Scheme://Host, and returns the
// response. Parse/transport errors are returned in Response.Error, not as a Go
// error, so the UI can always render something.
func (s *Sender) Send(ctx context.Context, in Request) Response {
	method, requestURI, header, body, err := parseRaw(in.Raw)
	if err != nil {
		return Response{Error: "parse request: " + err.Error()}
	}
	if in.Scheme == "" {
		in.Scheme = "https"
	}
	host := in.Host
	if host == "" {
		host = header.Get("Host")
	}
	if host == "" {
		return Response{Error: "no target host (set Host or the target field)"}
	}

	url := in.Scheme + "://" + host + requestURI
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return Response{Error: "build request: " + err.Error()}
	}
	// Apply edited headers. Host is special-cased onto req.Host.
	for k, vv := range header {
		if strings.EqualFold(k, "Host") {
			req.Host = vv[0]
			continue
		}
		if strings.EqualFold(k, "Content-Length") {
			continue // let the body length govern
		}
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}
	if len(body) > 0 {
		req.ContentLength = int64(len(body))
	}
	// Attach authenticated-session headers (if configured).
	if s.session != nil {
		s.session.Apply(req.Header)
	}

	start := time.Now()
	resp, err := s.tr.RoundTrip(req)
	if err != nil {
		return Response{Error: err.Error(), DurationMs: time.Since(start).Milliseconds()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	dur := time.Since(start).Milliseconds()

	binary := looksBinary(raw)
	out := Response{
		Status:     resp.StatusCode,
		StatusText: strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode))),
		Proto:      resp.Proto,
		Headers:    formatHeaders(resp.Header),
		BodyLen:    len(raw),
		Binary:     binary,
		DurationMs: dur,
	}
	if !binary {
		out.Body = string(raw)
	}
	return out
}

// parseRaw splits a raw HTTP/1.1 request into its parts. Line endings are
// normalized to CRLF first.
func parseRaw(raw string) (method, requestURI string, header http.Header, body []byte, err error) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	headPart := raw
	var bodyPart string
	if idx := strings.Index(raw, "\n\n"); idx >= 0 {
		headPart = raw[:idx]
		bodyPart = raw[idx+2:]
	}
	lines := strings.Split(headPart, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return "", "", nil, nil, fmt.Errorf("empty request line")
	}
	parts := strings.Fields(strings.TrimSpace(lines[0]))
	if len(parts) < 2 {
		return "", "", nil, nil, fmt.Errorf("malformed request line: %q", lines[0])
	}
	method = parts[0]
	requestURI = parts[1]
	if !strings.HasPrefix(requestURI, "/") && !strings.HasPrefix(requestURI, "http") {
		requestURI = "/" + requestURI
	}

	header = make(http.Header)
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		c := strings.IndexByte(line, ':')
		if c < 0 {
			continue
		}
		name := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(line[:c]))
		val := strings.TrimSpace(line[c+1:])
		header.Add(name, val)
	}
	return method, requestURI, header, []byte(bodyPart), nil
}

func formatHeaders(h http.Header) string {
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	// stable-ish order: keep as-is but join
	var b strings.Builder
	for _, k := range names {
		for _, v := range h[k] {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func looksBinary(b []byte) bool {
	n := len(b)
	if n > 2048 {
		n = 2048
	}
	nonPrintable := 0
	for i := 0; i < n; i++ {
		c := b[i]
		if c == 9 || c == 10 || c == 13 {
			continue
		}
		if c < 32 || c == 0 {
			nonPrintable++
		}
	}
	return nonPrintable > 8
}
