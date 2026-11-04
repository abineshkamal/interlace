// Package session holds headers (e.g. a session cookie or Authorization token)
// that Interlace attaches to outgoing Repeater, scanner and crawler requests,
// enabling authenticated testing. Beyond a flat global header list it supports
// per-host rules (different credentials per target) and CSRF auto-refresh
// (fetching a fresh anti-CSRF token before each state-changing request).
package session

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Header is a name/value pair applied to outgoing requests.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HostRule applies extra headers only to requests whose host matches Pattern
// (exact host, a dot-suffix like ".example.com", or "*" for all).
type HostRule struct {
	Pattern string   `json:"pattern"`
	Headers []Header `json:"headers"`
}

// CSRFConfig configures anti-CSRF token auto-refresh. When enabled, Interlace
// GETs URL before a state-changing request, extracts the first capture group of
// Regex from the response, and injects it as Name into the outgoing request at
// Inject ("header", "query" or "form").
type CSRFConfig struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
	Regex   string `json:"regex"`
	Inject  string `json:"inject"` // "header" | "query" | "form"
	Name    string `json:"name"`
}

// config is the on-disk shape (superset of the legacy []Header format).
type config struct {
	Headers   []Header   `json:"headers"`
	HostRules []HostRule `json:"hostRules,omitempty"`
	CSRF      CSRFConfig `json:"csrf,omitempty"`
}

// Session is a persisted, thread-safe set of headers, host rules and CSRF config.
type Session struct {
	mu        sync.RWMutex
	headers   []Header
	hostRules []HostRule
	csrf      CSRFConfig
	path      string

	// CSRF token cache.
	csrfRe    *regexp.Regexp
	csrfReSrc string
	tokVal    string
	tokAt     time.Time
	client    *http.Client
}

const csrfTokenTTL = 15 * time.Second

// Load reads the session from path. It accepts both the current object format
// and the legacy bare []Header array written by older versions.
func Load(path string) *Session {
	s := &Session{path: path, client: &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // testing proxy
	}}
	if b, err := os.ReadFile(path); err == nil {
		var cfg config
		if json.Unmarshal(b, &cfg) == nil && (cfg.Headers != nil || cfg.HostRules != nil || cfg.CSRF.URL != "") {
			s.headers = cfg.Headers
			s.hostRules = cfg.HostRules
			s.csrf = cfg.CSRF
		} else {
			var hs []Header
			if json.Unmarshal(b, &hs) == nil {
				s.headers = hs
			}
		}
	}
	return s
}

// Get returns the configured global headers.
func (s *Session) Get() []Header {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Header(nil), s.headers...)
}

// Set replaces and persists the global headers.
func (s *Session) Set(hs []Header) error {
	s.mu.Lock()
	var clean []Header
	for _, h := range hs {
		if h.Name != "" {
			clean = append(clean, h)
		}
	}
	s.headers = clean
	s.mu.Unlock()
	return s.save()
}

// HostRules returns the configured per-host rules.
func (s *Session) HostRules() []HostRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]HostRule(nil), s.hostRules...)
}

// SetHostRules replaces and persists the per-host rules.
func (s *Session) SetHostRules(rules []HostRule) error {
	s.mu.Lock()
	var clean []HostRule
	for _, r := range rules {
		if strings.TrimSpace(r.Pattern) != "" {
			clean = append(clean, r)
		}
	}
	s.hostRules = clean
	s.mu.Unlock()
	return s.save()
}

// CSRF returns the current CSRF configuration.
func (s *Session) CSRF() CSRFConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.csrf
}

// SetCSRF replaces and persists the CSRF configuration (and clears the token cache).
func (s *Session) SetCSRF(c CSRFConfig) error {
	s.mu.Lock()
	s.csrf = c
	s.tokVal = ""
	s.tokAt = time.Time{}
	s.mu.Unlock()
	return s.save()
}

func (s *Session) save() error {
	s.mu.RLock()
	cfg := config{
		Headers:   append([]Header(nil), s.headers...),
		HostRules: append([]HostRule(nil), s.hostRules...),
		CSRF:      s.csrf,
	}
	s.mu.RUnlock()
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o600)
}

// Apply adds the global headers, plus any matching host-rule headers, to h,
// overriding existing values so the authenticated identity is consistent.
func (s *Session) Apply(host string, h http.Header) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, hdr := range s.headers {
		h.Set(hdr.Name, hdr.Value)
	}
	host = hostOnly(host)
	for _, rule := range s.hostRules {
		if matchHost(rule.Pattern, host) {
			for _, hdr := range rule.Headers {
				h.Set(hdr.Name, hdr.Value)
			}
		}
	}
}

// Enabled reports whether any global header or host rule is configured.
func (s *Session) Enabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.headers) > 0 || len(s.hostRules) > 0
}

// CSRFToken fetches (and caches) a fresh anti-CSRF token per the configuration.
// It returns the header/param name, the token value, the injection location and
// ok=true when a token is available. It is safe to call on every request.
func (s *Session) CSRFToken(ctx context.Context) (name, value, inject string, ok bool) {
	s.mu.RLock()
	cfg := s.csrf
	cached := s.tokVal
	fresh := time.Since(s.tokAt) < csrfTokenTTL
	s.mu.RUnlock()

	if !cfg.Enabled || cfg.URL == "" || cfg.Regex == "" || cfg.Name == "" {
		return "", "", "", false
	}
	inject = cfg.Inject
	if inject == "" {
		inject = "header"
	}
	if cached != "" && fresh {
		return cfg.Name, cached, inject, true
	}

	re, err := s.compiledRegex(cfg.Regex)
	if err != nil {
		return "", "", "", false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.URL, nil)
	if err != nil {
		return "", "", "", false
	}
	// Carry the global session headers onto the token fetch so it is authenticated.
	s.Apply(hostFromURL(cfg.URL), req.Header)
	resp, err := s.client.Do(req)
	if err != nil {
		return "", "", "", false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	m := re.FindSubmatch(body)
	if len(m) < 2 {
		return "", "", "", false
	}
	tok := string(m[1])

	s.mu.Lock()
	s.tokVal = tok
	s.tokAt = time.Now()
	s.mu.Unlock()
	return cfg.Name, tok, inject, true
}

func (s *Session) compiledRegex(src string) (*regexp.Regexp, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.csrfRe != nil && s.csrfReSrc == src {
		return s.csrfRe, nil
	}
	re, err := regexp.Compile(src)
	if err != nil {
		return nil, err
	}
	s.csrfRe, s.csrfReSrc = re, src
	return re, nil
}

func matchHost(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = strings.ToLower(host)
	switch {
	case pattern == "" || pattern == "*":
		return true
	case strings.HasPrefix(pattern, "."):
		return host == pattern[1:] || strings.HasSuffix(host, pattern)
	default:
		return host == pattern
	}
}

func hostOnly(host string) string {
	if i := strings.IndexByte(host, ':'); i >= 0 {
		return host[:i]
	}
	return host
}

func hostFromURL(raw string) string {
	raw = strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")
	if i := strings.IndexAny(raw, "/?"); i >= 0 {
		raw = raw[:i]
	}
	return hostOnly(raw)
}
