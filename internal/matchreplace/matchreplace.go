// Package matchreplace rewrites requests and responses as they pass through the
// proxy, according to user-defined regex rules (an Interlace equivalent of
// Burp's match-and-replace).
package matchreplace

import (
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
)

// Rule parts.
const (
	ReqLine    = "req-line"    // the "METHOD path" of the request line
	ReqHeader  = "req-header"  // request header block
	ReqBody    = "req-body"    // request body
	RespHeader = "resp-header" // response header block
	RespBody   = "resp-body"   // response body
)

// Rule is one match-and-replace rule.
type Rule struct {
	Enabled bool   `json:"enabled"`
	Name    string `json:"name"`
	Part    string `json:"part"`
	Match   string `json:"match"`   // regex; empty means "append Replace" for header parts
	Replace string `json:"replace"` // replacement (supports $1 backrefs)
	Host    string `json:"host"`    // optional substring host filter

	re *regexp.Regexp
}

// Engine holds the compiled rules and persists them.
type Engine struct {
	mu    sync.RWMutex
	rules []Rule
	path  string
}

// Load reads rules from path (empty engine if none).
func Load(path string) *Engine {
	e := &Engine{path: path}
	if b, err := os.ReadFile(path); err == nil {
		var rules []Rule
		if json.Unmarshal(b, &rules) == nil {
			e.rules = rules
			e.compile()
		}
	}
	return e
}

// Get returns the current rules.
func (e *Engine) Get() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]Rule(nil), e.rules...)
}

// Set replaces and persists the rules.
func (e *Engine) Set(rules []Rule) error {
	e.mu.Lock()
	e.rules = rules
	e.compile()
	snapshot := append([]Rule(nil), e.rules...)
	e.mu.Unlock()

	b, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(e.path, b, 0o600)
}

func (e *Engine) compile() {
	for i := range e.rules {
		e.rules[i].re = nil
		if e.rules[i].Match != "" {
			if re, err := regexp.Compile(e.rules[i].Match); err == nil {
				e.rules[i].re = re
			}
		}
	}
}

func (e *Engine) active(part, host string) []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var out []Rule
	for _, r := range e.rules {
		if !r.Enabled || r.Part != part {
			continue
		}
		if r.Host != "" && !strings.Contains(host, r.Host) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// Enabled reports whether any rule is active (fast path).
func (e *Engine) Enabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, r := range e.rules {
		if r.Enabled {
			return true
		}
	}
	return false
}

// ApplyRequestLine rewrites "method path" and returns the new pair.
func (e *Engine) ApplyRequestLine(host, method, path string) (string, string) {
	line := method + " " + path
	for _, r := range e.active(ReqLine, host) {
		if r.re != nil {
			line = r.re.ReplaceAllString(line, r.Replace)
		}
	}
	if i := strings.IndexByte(line, ' '); i >= 0 {
		return line[:i], line[i+1:]
	}
	return method, path
}

// ApplyHeaders rewrites a header map in place for the given part.
func (e *Engine) ApplyHeaders(part, host string, h http.Header) {
	rules := e.active(part, host)
	if len(rules) == 0 {
		return
	}
	block := headersToBlock(h)
	changed := false
	for _, r := range rules {
		if r.Match == "" { // append
			block += r.Replace + "\n"
			changed = true
			continue
		}
		if r.re != nil && r.re.MatchString(block) {
			block = r.re.ReplaceAllString(block, r.Replace)
			changed = true
		}
	}
	if changed {
		blockToHeaders(block, h)
	}
}

// ApplyBody rewrites a body for the given part.
func (e *Engine) ApplyBody(part, host string, body []byte) []byte {
	rules := e.active(part, host)
	if len(rules) == 0 {
		return body
	}
	s := string(body)
	for _, r := range rules {
		if r.re != nil {
			s = r.re.ReplaceAllString(s, r.Replace)
		}
	}
	return []byte(s)
}

func headersToBlock(h http.Header) string {
	var b strings.Builder
	for name, vals := range h {
		for _, v := range vals {
			b.WriteString(name + ": " + v + "\n")
		}
	}
	return b.String()
}

func blockToHeaders(block string, h http.Header) {
	for k := range h {
		delete(h, k)
	}
	for _, ln := range strings.Split(block, "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		c := strings.IndexByte(ln, ':')
		if c < 0 {
			continue
		}
		h.Add(strings.TrimSpace(ln[:c]), strings.TrimSpace(ln[c+1:]))
	}
}
