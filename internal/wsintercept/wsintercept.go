// Package wsintercept pauses individual WebSocket messages for manual
// edit/drop before they are relayed, analogous to package intercept for HTTP.
package wsintercept

import (
	"sync"
	"sync/atomic"

	"interlace/internal/hub"
)

// Held is a paused WebSocket message.
type Held struct {
	ID        int64  `json:"id"`
	Host      string `json:"host"`
	URL       string `json:"url"`
	Direction string `json:"direction"`
	Opcode    string `json:"opcode"`
	Payload   string `json:"payload"`

	resume chan decision
}

type decision struct {
	drop    bool
	payload string
}

// Interceptor coordinates paused WebSocket messages.
type Interceptor struct {
	enabled atomic.Bool
	seq     atomic.Int64

	mu   sync.Mutex
	held map[int64]*Held
	hub  *hub.Hub
}

// New creates an Interceptor.
func New(h *hub.Hub) *Interceptor {
	return &Interceptor{held: make(map[int64]*Held), hub: h}
}

// Enabled reports whether WS interception is on.
func (ic *Interceptor) Enabled() bool { return ic.enabled.Load() }

// SetEnabled toggles interception; turning it off forwards all held messages.
func (ic *Interceptor) SetEnabled(on bool) {
	ic.enabled.Store(on)
	if !on {
		ic.mu.Lock()
		held := ic.held
		ic.held = make(map[int64]*Held)
		ic.mu.Unlock()
		for _, h := range held {
			h.resume <- decision{payload: h.Payload}
		}
	}
	ic.notify()
}

// HoldWS blocks until the user resolves this message, returning the (possibly
// edited) payload and whether to drop it.
func (ic *Interceptor) HoldWS(host, url, dir, opcode, payload string) (string, bool) {
	h := &Held{
		ID: ic.seq.Add(1), Host: host, URL: url, Direction: dir, Opcode: opcode, Payload: payload,
		resume: make(chan decision, 1),
	}
	ic.mu.Lock()
	ic.held[h.ID] = h
	ic.mu.Unlock()
	ic.notify()

	d := <-h.resume
	return d.payload, d.drop
}

// Resolve applies a decision to a held message.
func (ic *Interceptor) Resolve(id int64, action, payload string) bool {
	ic.mu.Lock()
	h, ok := ic.held[id]
	if ok {
		delete(ic.held, id)
	}
	ic.mu.Unlock()
	if !ok {
		return false
	}
	if action != "drop" && payload == "" {
		payload = h.Payload
	}
	h.resume <- decision{drop: action == "drop", payload: payload}
	ic.notify()
	return true
}

// Pending returns currently held messages.
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
		ic.hub.Broadcast([]byte(`{"type":"wsintercept-change"}`))
	}
}
