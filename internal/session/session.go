// Package session holds headers (e.g. a session cookie or Authorization token)
// that Interlace attaches to outgoing Repeater, scanner and crawler requests,
// enabling authenticated testing.
package session

import (
	"encoding/json"
	"net/http"
	"os"
	"sync"
)

// Header is a name/value pair applied to outgoing requests.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Session is a persisted, thread-safe set of headers.
type Session struct {
	mu      sync.RWMutex
	headers []Header
	path    string
}

// Load reads the session from path (empty if none).
func Load(path string) *Session {
	s := &Session{path: path}
	if b, err := os.ReadFile(path); err == nil {
		var hs []Header
		if json.Unmarshal(b, &hs) == nil {
			s.headers = hs
		}
	}
	return s
}

// Get returns the configured headers.
func (s *Session) Get() []Header {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Header(nil), s.headers...)
}

// Set replaces and persists the headers.
func (s *Session) Set(hs []Header) error {
	s.mu.Lock()
	var clean []Header
	for _, h := range hs {
		if h.Name != "" {
			clean = append(clean, h)
		}
	}
	s.headers = clean
	snapshot := append([]Header(nil), s.headers...)
	s.mu.Unlock()

	b, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o600)
}

// Apply adds the session headers to h, overriding any existing values so the
// authenticated identity is consistent.
func (s *Session) Apply(h http.Header) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, hdr := range s.headers {
		h.Set(hdr.Name, hdr.Value)
	}
}

// Enabled reports whether any header is configured.
func (s *Session) Enabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.headers) > 0
}
