package proxy

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"time"

	"interlace/internal/model"
)

// isWebSocket reports whether req is a WebSocket upgrade handshake.
func isWebSocket(h interface{ Get(string) string }) bool {
	return strings.EqualFold(h.Get("Upgrade"), "websocket")
}

// handleWebSocket proxies a WebSocket connection, relaying frames in both
// directions while logging each text/binary message via OnWS. clientConn/br is
// the (decrypted) client side; req is the already-parsed handshake.
func (p *Proxy) handleWebSocket(clientConn net.Conn, br *bufio.Reader, method, requestURI string,
	header map[string][]string, scheme, authority string) {

	// Dial upstream.
	hostport := authority
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		if scheme == "wss" {
			hostport += ":443"
		} else {
			hostport += ":80"
		}
	}
	var upstream net.Conn
	var err error
	if scheme == "wss" {
		upstream, err = tls.Dial("tcp", hostport, &tls.Config{InsecureSkipVerify: p.opts.InsecureUpstream, ServerName: stripPort(authority)}) //nolint:gosec
	} else {
		upstream, err = net.Dial("tcp", hostport)
	}
	if err != nil {
		return
	}
	defer upstream.Close()

	// Forward the handshake request to upstream. http.ReadRequest strips Host
	// into req.Host, so re-add it explicitly from the authority.
	var hs strings.Builder
	hs.WriteString(method + " " + requestURI + " HTTP/1.1\r\n")
	hs.WriteString("Host: " + authority + "\r\n")
	for name, vals := range header {
		if strings.EqualFold(name, "Host") {
			continue
		}
		for _, v := range vals {
			hs.WriteString(name + ": " + v + "\r\n")
		}
	}
	hs.WriteString("\r\n")
	if _, err := upstream.Write([]byte(hs.String())); err != nil {
		return
	}

	// Read the upstream handshake response and relay it to the client.
	upBr := bufio.NewReader(upstream)
	respHead, err := readHTTPHead(upBr)
	if err != nil {
		return
	}
	if _, err := clientConn.Write([]byte(respHead)); err != nil {
		return
	}
	if !strings.Contains(respHead, " 101 ") {
		// Not an upgrade; just pump remaining bytes through and stop logging.
		go io.Copy(clientConn, upBr)
		io.Copy(upstream, br)
		return
	}

	host := stripPort(authority)
	wsURL := scheme + "://" + authority + requestURI

	// Relay both directions, parsing frames so each message can be logged and
	// optionally held for interception. Frames toward the server are masked.
	done := make(chan struct{}, 2)
	go func() { p.relayFrames(upstream, br, true, host, wsURL, "send"); done <- struct{}{} }()
	go func() { p.relayFrames(clientConn, upBr, false, host, wsURL, "recv"); done <- struct{}{} }()
	<-done
}

// relayFrames reads WebSocket frames from srcBr and writes them to dst (masking
// toward the server), logging and optionally intercepting data messages.
func (p *Proxy) relayFrames(dst io.Writer, srcBr *bufio.Reader, maskToDst bool, host, url, dir string) {
	for {
		opcode, payload, fin, err := readFrame(srcBr)
		if err != nil {
			return
		}
		if fin && (opcode == 0x1 || opcode == 0x2) {
			opStr := "text"
			if opcode == 0x2 {
				opStr = "binary"
			}
			if p.opts.WSInterceptor != nil && p.opts.WSInterceptor.Enabled() {
				edited, drop := p.opts.WSInterceptor.HoldWS(host, url, dir, opStr, string(payload))
				if drop {
					continue
				}
				payload = []byte(edited)
			}
			p.emitWS(host, url, dir, opStr, payload)
		}
		if err := writeFrame(dst, opcode, payload, fin, maskToDst); err != nil {
			return
		}
	}
}

func (p *Proxy) emitWS(host, url, dir, opcode string, payload []byte) {
	if p.opts.OnWS == nil {
		return
	}
	p.opts.OnWS(&model.WSMessage{
		Time: time.Now(), Host: host, URL: url, Direction: dir,
		Opcode: opcode, Payload: string(payload),
	})
}

// readFrame reads a single WebSocket frame, unmasking the payload if needed.
func readFrame(br *bufio.Reader) (opcode byte, payload []byte, fin bool, err error) {
	b0, err := br.ReadByte()
	if err != nil {
		return 0, nil, false, err
	}
	fin = b0&0x80 != 0
	opcode = b0 & 0x0f
	b1, err := br.ReadByte()
	if err != nil {
		return 0, nil, false, err
	}
	masked := b1&0x80 != 0
	ln := int(b1 & 0x7f)
	switch ln {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(br, ext[:]); err != nil {
			return
		}
		ln = int(ext[0])<<8 | int(ext[1])
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(br, ext[:]); err != nil {
			return
		}
		ln = 0
		for _, b := range ext {
			ln = ln<<8 | int(b)
		}
	}
	if ln < 0 || ln > 32<<20 {
		return 0, nil, false, io.ErrUnexpectedEOF
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(br, mask[:]); err != nil {
			return
		}
	}
	payload = make([]byte, ln)
	if _, err = io.ReadFull(br, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return opcode, payload, fin, nil
}

// writeFrame encodes a WebSocket frame, masking the payload when mask is true
// (required for client→server frames).
func writeFrame(w io.Writer, opcode byte, payload []byte, fin, mask bool) error {
	var hdr []byte
	b0 := opcode
	if fin {
		b0 |= 0x80
	}
	hdr = append(hdr, b0)
	var b1 byte
	if mask {
		b1 = 0x80
	}
	ln := len(payload)
	switch {
	case ln < 126:
		hdr = append(hdr, b1|byte(ln))
	case ln < 65536:
		hdr = append(hdr, b1|126, byte(ln>>8), byte(ln))
	default:
		hdr = append(hdr, b1|127)
		for i := 7; i >= 0; i-- {
			hdr = append(hdr, byte(ln>>(8*i)))
		}
	}
	if mask {
		var key [4]byte
		_, _ = rand.Read(key[:])
		hdr = append(hdr, key[:]...)
		masked := make([]byte, ln)
		for i := 0; i < ln; i++ {
			masked[i] = payload[i] ^ key[i%4]
		}
		if _, err := w.Write(hdr); err != nil {
			return err
		}
		_, err := w.Write(masked)
		return err
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// readHTTPHead reads an HTTP message head (through the blank line) as a string.
func readHTTPHead(br *bufio.Reader) (string, error) {
	var b strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return b.String(), err
		}
		b.WriteString(line)
		if line == "\r\n" || line == "\n" {
			return b.String(), nil
		}
	}
}

