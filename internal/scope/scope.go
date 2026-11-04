// Package scope defines which hosts Interlace is permitted to actively attack.
// Passive observation happens on all proxied traffic, but active scanning and
// crawling only fire at hosts explicitly placed in scope — the core safeguard
// that keeps Interlace a tool for authorized testing.
package scope

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
)

// Scope holds include/exclude host rules and persists them to disk.
type Scope struct {
	mu      sync.RWMutex
	include []string
	exclude []string
	path    string
}

type persisted struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

// Load reads scope rules from path, returning an empty scope if none exist.
func Load(path string) *Scope {
	s := &Scope{path: path}
	if b, err := os.ReadFile(path); err == nil {
		var p persisted
		if json.Unmarshal(b, &p) == nil {
			s.include = p.Include
			s.exclude = p.Exclude
		}
	}
	return s
}

// Get returns the current include/exclude rule lists.
func (s *Scope) Get() (include, exclude []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.include...), append([]string(nil), s.exclude...)
}

// Set replaces the rules and persists them.
func (s *Scope) Set(include, exclude []string) error {
	s.mu.Lock()
	s.include = cleanList(include)
	s.exclude = cleanList(exclude)
	inc, exc := append([]string(nil), s.include...), append([]string(nil), s.exclude...)
	s.mu.Unlock()

	b, err := json.MarshalIndent(persisted{Include: inc, Exclude: exc}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o600)
}

// InScope reports whether host is permitted for active actions. A host is in
// scope when it matches an include rule and no exclude rule. With no include
// rules, nothing is in scope (fail-closed).
func (s *Scope) InScope(host string) bool {
	host = strings.ToLower(hostOnly(host))
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.include) == 0 {
		return false
	}
	for _, e := range s.exclude {
		if match(e, host) {
			return false
		}
	}
	for _, i := range s.include {
		if match(i, host) {
			return true
		}
	}
	return false
}

// match supports exact hosts and "*.domain" wildcards (which also match the
// bare domain). Matching is case-insensitive.
func match(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return false
	}
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		base := pattern[2:]
		return host == base || strings.HasSuffix(host, "."+base)
	}
	return false
}

func cleanList(in []string) []string {
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
