// Package macro records and replays a sequence of requests (a login flow) to
// obtain an authenticated session. Replaying runs the steps through a shared
// cookie jar, so cookies set by earlier steps are carried to later ones, and
// returns the resulting Cookie header to attach to future requests.
package macro

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Step is one request in the macro.
type Step struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Raw    string `json:"raw"`
}

// Store persists the ordered flow IDs that make up the login macro.
type Store struct {
	mu      sync.RWMutex
	flowIDs []int64
	path    string
}

// Load reads the saved macro (flow IDs).
func Load(path string) *Store {
	s := &Store{path: path}
	if b, err := os.ReadFile(path); err == nil {
		var ids []int64
		if json.Unmarshal(b, &ids) == nil {
			s.flowIDs = ids
		}
	}
	return s
}

// Get returns the saved flow IDs.
func (s *Store) Get() []int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]int64(nil), s.flowIDs...)
}

// Set replaces and persists the flow IDs.
func (s *Store) Set(ids []int64) error {
	s.mu.Lock()
	s.flowIDs = ids
	snapshot := append([]int64(nil), ids...)
	s.mu.Unlock()
	b, _ := json.MarshalIndent(snapshot, "", "  ")
	return os.WriteFile(s.path, b, 0o600)
}

// Replay runs the steps in order through a shared cookie jar and returns the
// resulting Cookie header value for the final step's host.
func Replay(ctx context.Context, steps []Step, insecure bool) (string, error) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:     jar,
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec
		},
	}
	var lastURL *url.URL
	for _, s := range steps {
		method, reqURI, header, body := parseRaw(s.Raw)
		scheme := s.Scheme
		if scheme == "" {
			scheme = "https"
		}
		u := scheme + "://" + s.Host + reqURI
		req, err := http.NewRequestWithContext(ctx, method, u, strings.NewReader(body))
		if err != nil {
			continue
		}
		for k, vv := range header {
			if strings.EqualFold(k, "host") || strings.EqualFold(k, "content-length") {
				continue
			}
			for _, v := range vv {
				req.Header.Add(k, v)
			}
		}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		lastURL = req.URL
	}
	if lastURL == nil {
		return "", nil
	}
	var parts []string
	for _, c := range jar.Cookies(lastURL) {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; "), nil
}

func parseRaw(raw string) (method, reqURI string, header http.Header, body string) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	head := raw
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		head, body = raw[:i], raw[i+2:]
	}
	lines := strings.Split(head, "\n")
	header = http.Header{}
	if len(lines) == 0 {
		return "GET", "/", header, ""
	}
	parts := strings.Fields(strings.TrimSpace(lines[0]))
	if len(parts) >= 2 {
		method, reqURI = parts[0], parts[1]
	} else {
		method, reqURI = "GET", "/"
	}
	for _, ln := range lines[1:] {
		c := strings.IndexByte(ln, ':')
		if c < 0 {
			continue
		}
		header.Add(strings.TrimSpace(ln[:c]), strings.TrimSpace(ln[c+1:]))
	}
	return method, reqURI, header, body
}
