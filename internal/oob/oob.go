// Package oob implements an out-of-band interaction server (an Interlace
// equivalent of Burp Collaborator, HTTP-based). It mints unique tokens, hands
// out callback URLs embedding them, and records any inbound request that
// carries a token — revealing blind vulnerabilities such as blind SSRF, blind
// XXE and out-of-band command execution where the target calls back to us.
package oob

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"interlace/internal/hub"
)

// Interaction is a single inbound callback.
type Interaction struct {
	Token      string    `json:"token"`
	Time       time.Time `json:"time"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	RemoteAddr string    `json:"remoteAddr"`
	UserAgent  string    `json:"userAgent"`
}

// Server records out-of-band interactions.
type Server struct {
	baseURL string
	hub     *hub.Hub

	mu           sync.RWMutex
	tokens       map[string]bool
	byToken      map[string][]Interaction
	interactions []Interaction // recent, capped
}

const maxInteractions = 500

// New creates an OOB server whose callback URLs are rooted at baseURL
// (e.g. "http://127.0.0.1:8082"). The hub, if non-nil, receives live interactions.
func New(baseURL string, h *hub.Hub) *Server {
	return &Server{
		baseURL: strings.TrimRight(baseURL, "/"),
		hub:     h,
		tokens:  make(map[string]bool),
		byToken: make(map[string][]Interaction),
	}
}

// NewToken mints a token and returns it with a full callback URL.
func (s *Server) NewToken() (token, url string) {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	token = "ilx" + hex.EncodeToString(b)
	s.mu.Lock()
	s.tokens[token] = true
	s.mu.Unlock()
	return token, s.baseURL + "/" + token
}

// BaseURL returns the configured callback root.
func (s *Server) BaseURL() string { return s.baseURL }

// Handler records every inbound request, correlating by the first path segment
// (or any embedded token) and always returning a tiny response.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		first := path
		if i := strings.IndexByte(first, '/'); i >= 0 {
			first = first[:i]
		}
		token := ""
		s.mu.RLock()
		if s.tokens[first] {
			token = first
		}
		s.mu.RUnlock()
		// Also catch tokens embedded anywhere in the path.
		if token == "" {
			s.mu.RLock()
			for t := range s.tokens {
				if strings.Contains(path, t) {
					token = t
					break
				}
			}
			s.mu.RUnlock()
		}

		it := Interaction{
			Token:      token,
			Time:       time.Now(),
			Method:     r.Method,
			Path:       r.URL.String(),
			RemoteAddr: r.RemoteAddr,
			UserAgent:  r.UserAgent(),
		}
		s.record(it)

		w.Header().Set("Server", "Interlace-OOB")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("interlace\n"))
	})
}

func (s *Server) record(it Interaction) {
	s.mu.Lock()
	s.interactions = append(s.interactions, it)
	if len(s.interactions) > maxInteractions {
		s.interactions = s.interactions[len(s.interactions)-maxInteractions:]
	}
	if it.Token != "" {
		s.byToken[it.Token] = append(s.byToken[it.Token], it)
	}
	s.mu.Unlock()
	if s.hub != nil {
		if msg, err := json.Marshal(it); err == nil {
			s.hub.Broadcast(msg)
		}
	}
}

// Hits reports whether any interaction has been recorded for token.
func (s *Server) Hits(token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byToken[token]) > 0
}

// Recent returns up to limit most-recent interactions (newest first).
func (s *Server) Recent(limit int) []Interaction {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.interactions) {
		limit = len(s.interactions)
	}
	out := make([]Interaction, 0, limit)
	for i := len(s.interactions) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.interactions[i])
	}
	return out
}
