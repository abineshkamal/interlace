// Package intercept lets the user pause in-flight proxy requests, edit or drop
// them, then forward them. When interception is enabled, the proxy calls Hold
// for each request, which blocks until the UI submits a decision.
package intercept

import (
	"strings"
	"sync"
	"sync/atomic"

	"interlace/internal/hub"
)

// Held is a paused request or response awaiting a user decision.
type Held struct {
	ID     int64  `json:"id"`
	Kind   string `json:"kind"` // "request" or "response"
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Status int    `json:"status,omitempty"`
	Raw    string `json:"raw"`

	resume chan decision
}

type decision struct {
	drop bool
	raw  string
}

// Interceptor coordinates paused requests and responses.
type Interceptor struct {
	enabled     atomic.Bool
	respEnabled atomic.Bool
	seq         atomic.Int64

	mu     sync.Mutex
	held   map[int64]*Held
	filter string // only intercept hosts containing this substring (empty = all)
	hub    *hub.Hub
}

// New creates an Interceptor. The hub (if non-nil) is notified of changes.
func New(h *hub.Hub) *Interceptor {
	return &Interceptor{held: make(map[int64]*Held), hub: h}
}

// Enabled reports whether request interception is on.
func (ic *Interceptor) Enabled() bool { return ic.enabled.Load() }

// RespEnabled reports whether response interception is on.
func (ic *Interceptor) RespEnabled() bool { return ic.respEnabled.Load() }

// SetFilter restricts interception to hosts containing substr (empty = all).
func (ic *Interceptor) SetFilter(substr string) {
	ic.mu.Lock()
	ic.filter = substr
	ic.mu.Unlock()
}

func (ic *Interceptor) matches(host string) bool {
	ic.mu.Lock()
	f := ic.filter
	ic.mu.Unlock()
	return f == "" || strings.Contains(host, f)
}

// SetEnabled toggles request interception. Turning it off releases all held.
func (ic *Interceptor) SetEnabled(on bool) {
	ic.enabled.Store(on)
	if !on {
		ic.releaseAll()
	}
	ic.notify()
}

// SetRespEnabled toggles response interception. Turning it off releases all held.
func (ic *Interceptor) SetRespEnabled(on bool) {
	ic.respEnabled.Store(on)
	if !on {
		ic.releaseAll()
	}
	ic.notify()
}

func (ic *Interceptor) releaseAll() {
	ic.mu.Lock()
	held := ic.held
	ic.held = make(map[int64]*Held)
	ic.mu.Unlock()
	for _, h := range held {
		h.resume <- decision{drop: false, raw: h.Raw}
	}
}

// Hold blocks until the user resolves this request. It returns the (possibly
// edited) raw request to send, and whether to drop it.
func (ic *Interceptor) Hold(scheme, host, method, url, raw string) (string, bool) {
	if !ic.matches(host) {
		return raw, false
	}
	h := &Held{
		ID: ic.seq.Add(1), Kind: "request",
		Scheme: scheme, Host: host, Method: method, URL: url, Raw: raw,
		resume: make(chan decision, 1),
	}
	ic.mu.Lock()
	ic.held[h.ID] = h
	ic.mu.Unlock()
	ic.notify()

	d := <-h.resume
	return d.raw, d.drop
}

// HoldResponse blocks until the user resolves a paused response. It returns the
// (possibly edited) raw response and whether to drop it.
func (ic *Interceptor) HoldResponse(scheme, host, method, url string, status int, raw string) (string, bool) {
	if !ic.matches(host) {
		return raw, false
	}
	h := &Held{
		ID: ic.seq.Add(1), Kind: "response",
		Scheme: scheme, Host: host, Method: method, URL: url, Status: status, Raw: raw,
		resume: make(chan decision, 1),
	}
	ic.mu.Lock()
	ic.held[h.ID] = h
	ic.mu.Unlock()
	ic.notify()

	d := <-h.resume
	return d.raw, d.drop
}

// Resolve applies a decision to a held request. action is "forward" or "drop";
// raw is the (possibly edited) request for forwarding.
func (ic *Interceptor) Resolve(id int64, action, raw string) bool {
	ic.mu.Lock()
	h, ok := ic.held[id]
	if ok {
		delete(ic.held, id)
	}
	ic.mu.Unlock()
	if !ok {
		return false
	}
	if raw == "" {
		raw = h.Raw
	}
	h.resume <- decision{drop: action == "drop", raw: raw}
	ic.notify()
	return true
}

// Pending returns the currently held requests.
func (ic *Interceptor) Pending() []*Held {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	out := make([]*Held, 0, len(ic.held))
	for _, h := range ic.held {
		out = append(out, h)
	}
	return out
}

func (ic *Interceptor) notify() {
	if ic.hub != nil {
		ic.hub.Broadcast([]byte(`{"type":"intercept-change"}`))
	}
}
