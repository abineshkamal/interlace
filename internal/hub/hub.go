// Package hub is a tiny publish/subscribe broadcaster used to stream newly
// captured flows to connected UI clients over Server-Sent Events.
package hub

import "sync"

// Hub fans out messages (pre-serialized JSON bytes) to all subscribers.
type Hub struct {
	mu   sync.RWMutex
	subs map[chan []byte]struct{}
}

// New creates an empty Hub.
func New() *Hub {
	return &Hub{subs: make(map[chan []byte]struct{})}
}

// Subscribe registers a new subscriber and returns its channel plus an
// unsubscribe function the caller must defer.
func (h *Hub) Subscribe() (<-chan []byte, func()) {
	ch := make(chan []byte, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()

	return ch, func() {
		h.mu.Lock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
}

// Broadcast delivers msg to every subscriber. Slow subscribers whose buffer is
// full are skipped rather than blocking the caller (the proxy hot path).
func (h *Hub) Broadcast(msg []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.subs {
		select {
		case ch <- msg:
		default: // drop for a subscriber that can't keep up
		}
	}
}
