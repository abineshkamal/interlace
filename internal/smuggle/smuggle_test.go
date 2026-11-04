package smuggle

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeServer emulates a proxy/back-end chain. When vulnerable, any request that
// carries a Transfer-Encoding header is left hanging (as a desynced back-end
// would block awaiting body bytes); otherwise every request is answered at once.
func fakeServer(t *testing.T, vulnerable bool) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(6 * time.Second))
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				if vulnerable && strings.Contains(string(buf[:n]), "Transfer-Encoding") {
					time.Sleep(probeTimeout + 2*time.Second) // outlast the client's read deadline
				}
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi"))
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func TestDetectVulnerable(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test skipped in -short")
	}
	addr, stop := fakeServer(t, true)
	defer stop()

	results, probes := Detect(context.Background(), "http", addr, "/", "")
	if probes != 3 {
		t.Errorf("expected 3 probes, got %d", probes)
	}
	if len(results) == 0 {
		t.Fatalf("expected a smuggling finding on the vulnerable chain, got none")
	}
	// Both CL.TE and TE.CL carry Transfer-Encoding, so both stall.
	techniques := map[string]bool{}
	for _, r := range results {
		techniques[r.Technique] = true
		if r.Evidence == "" {
			t.Errorf("result %q missing evidence", r.Technique)
		}
	}
	if !techniques["CL.TE"] || !techniques["TE.CL"] {
		t.Errorf("expected both CL.TE and TE.CL, got %v", techniques)
	}
}

func TestDetectSafe(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test skipped in -short")
	}
	addr, stop := fakeServer(t, false)
	defer stop()

	results, probes := Detect(context.Background(), "http", addr, "/", "")
	if probes != 3 {
		t.Errorf("expected 3 probes, got %d", probes)
	}
	if len(results) != 0 {
		t.Errorf("expected no findings on a healthy server, got %v", results)
	}
}

func TestDetectUnreachable(t *testing.T) {
	// A closed port should not panic and should report nothing.
	results, _ := Detect(context.Background(), "http", "127.0.0.1:1", "/", "")
	if len(results) != 0 {
		t.Errorf("expected no findings for an unreachable host, got %v", results)
	}
}
