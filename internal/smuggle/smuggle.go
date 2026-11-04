// Package smuggle implements timing-based HTTP request smuggling (desync)
// detection. Smuggling arises when a front-end proxy and a back-end server
// disagree on where one request ends and the next begins — typically because
// one honours the Content-Length header and the other the Transfer-Encoding
// header. Detection here follows the classic PortSwigger timing technique: a
// crafted request that, on a vulnerable chain, leaves the back-end waiting for
// body bytes that never arrive, producing a measurable delay. Non-vulnerable
// servers answer immediately.
//
// Because the probes rely on sending deliberately malformed, conflicting
// framing headers, they cannot go through net/http (which normalises and
// rejects them). smuggle writes raw bytes over its own TCP/TLS socket. Callers
// MUST confirm the target is in scope before invoking Detect — these probes
// generate traffic and briefly tie up a back-end worker.
package smuggle

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// Timing thresholds. A vulnerable chain blocks until our read deadline; a
// healthy server responds well under the baseline ceiling.
const (
	probeTimeout    = 7 * time.Second // read deadline for a smuggling probe
	detectThreshold = 5 * time.Second // elapsed >= this => likely desync
	baselineMax     = 3 * time.Second // baseline must be faster than this to trust a result
	dialTimeout     = 10 * time.Second
)

// Result is a confirmed (timing-indicated) smuggling finding.
type Result struct {
	Technique string // "CL.TE" or "TE.CL"
	Evidence  string
}

// Detect runs CL.TE and TE.CL timing probes against scheme://host at path and
// returns any techniques that produced a smuggling-indicative delay. hostHeader
// is the Host value to send (defaults to host). It returns the number of probe
// requests sent alongside the results.
func Detect(ctx context.Context, scheme, host, path, hostHeader string) ([]Result, int) {
	if path == "" {
		path = "/"
	}
	if hostHeader == "" {
		hostHeader = hostOnly(host)
	}

	probes := 0

	// Baseline: a well-formed request. If the server is already slow (or
	// unreachable), timing comparison is meaningless, so bail.
	baseline := "POST " + path + " HTTP/1.1\r\n" +
		"Host: " + hostHeader + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 0\r\n" +
		"Connection: close\r\n\r\n"
	baseElapsed, baseErr := sendRaw(ctx, scheme, host, []byte(baseline), probeTimeout)
	probes++
	if baseErr != nil && !isTimeout(baseErr) && baseElapsed == 0 {
		return nil, probes // couldn't connect at all
	}
	if baseElapsed >= baselineMax {
		return nil, probes // server too slow to trust timing
	}

	var results []Result

	// CL.TE: front-end uses Content-Length (4 => forwards "1\r\nA"), back-end
	// uses Transfer-Encoding and reads chunk "A" then blocks awaiting the next
	// chunk, which never arrives.
	clte := "POST " + path + " HTTP/1.1\r\n" +
		"Host: " + hostHeader + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Content-Length: 4\r\n\r\n" +
		"1\r\nA\r\nX"
	if el, err := sendRaw(ctx, scheme, host, []byte(clte), probeTimeout); isDelay(el, err) {
		results = append(results, Result{
			Technique: "CL.TE",
			Evidence:  fmt.Sprintf("CL.TE probe stalled %s (baseline %s) — front-end used Content-Length, back-end Transfer-Encoding", round(el), round(baseElapsed)),
		})
	}
	probes++

	// TE.CL: front-end uses Transfer-Encoding (reads terminating "0" chunk and
	// forwards), back-end uses Content-Length (6) and blocks awaiting a byte that
	// stays behind the chunk terminator.
	tecl := "POST " + path + " HTTP/1.1\r\n" +
		"Host: " + hostHeader + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Content-Length: 6\r\n\r\n" +
		"0\r\n\r\nX"
	if el, err := sendRaw(ctx, scheme, host, []byte(tecl), probeTimeout); isDelay(el, err) {
		results = append(results, Result{
			Technique: "TE.CL",
			Evidence:  fmt.Sprintf("TE.CL probe stalled %s (baseline %s) — front-end used Transfer-Encoding, back-end Content-Length", round(el), round(baseElapsed)),
		})
	}
	probes++

	return results, probes
}

// isDelay reports whether a probe's outcome indicates a desync: it blocked up to
// (or past) the detect threshold, whether that surfaced as a timeout error or a
// slow but successful read.
func isDelay(elapsed time.Duration, err error) bool {
	if err != nil && !isTimeout(err) {
		return false // a hard connection error is not a timing signal
	}
	return elapsed >= detectThreshold
}

// sendRaw opens a TCP (or TLS) connection to scheme://host, writes payload
// verbatim, and measures the time from the write until the first response byte
// arrives or the read deadline fires. The returned duration is that wait; a
// deadline-exceeded error with a near-timeout duration is the smuggling signal.
func sendRaw(ctx context.Context, scheme, host string, payload []byte, timeout time.Duration) (time.Duration, error) {
	addr := withPort(host, scheme)
	d := net.Dialer{Timeout: dialTimeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}

	var conn net.Conn = raw
	if scheme == "https" {
		tconn := tls.Client(raw, &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // timing probe; cert validity is irrelevant
			ServerName:         hostOnly(host),
			NextProtos:         []string{"http/1.1"}, // smuggling is an HTTP/1.1 concept
		})
		if err := tconn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return 0, err
		}
		conn = tconn
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	start := time.Now()
	if _, err := conn.Write(payload); err != nil {
		return time.Since(start), err
	}
	buf := make([]byte, 512)
	_, rerr := conn.Read(buf)
	return time.Since(start), rerr
}

func isTimeout(err error) bool {
	var ne net.Error
	if errorsAs(err, &ne) {
		return ne.Timeout()
	}
	return false
}

// errorsAs is a tiny local stand-in to avoid importing errors just for one call
// site while keeping the net.Error type assertion correct across wrapping.
func errorsAs(err error, target *net.Error) bool {
	for err != nil {
		if ne, ok := err.(net.Error); ok {
			*target = ne
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func withPort(host, scheme string) string {
	if strings.Contains(host, ":") {
		return host
	}
	if scheme == "https" {
		return host + ":443"
	}
	return host + ":80"
}

func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func round(d time.Duration) time.Duration { return d.Round(100 * time.Millisecond) }
