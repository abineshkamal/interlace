// Package notify posts newly discovered findings to a webhook (Slack/Discord/
// generic compatible) when they meet a severity threshold.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"time"

	"interlace/internal/scanner"
)

// Config holds the webhook settings.
type Config struct {
	WebhookURL  string `json:"webhookUrl"`
	MinSeverity string `json:"minSeverity"` // high|medium|low|info
}

// Notifier posts findings to the configured webhook.
type Notifier struct {
	mu   sync.RWMutex
	cfg  Config
	path string
	http *http.Client
}

// Load reads notify config from path.
func Load(path string) *Notifier {
	n := &Notifier{path: path, http: &http.Client{Timeout: 10 * time.Second}}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &n.cfg)
	}
	if n.cfg.MinSeverity == "" {
		n.cfg.MinSeverity = scanner.High
	}
	return n
}

// Get returns the current config.
func (n *Notifier) Get() Config {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.cfg
}

// Set updates and persists the config.
func (n *Notifier) Set(c Config) error {
	n.mu.Lock()
	n.cfg = c
	if n.cfg.MinSeverity == "" {
		n.cfg.MinSeverity = scanner.High
	}
	snap := n.cfg
	n.mu.Unlock()
	b, _ := json.MarshalIndent(snap, "", "  ")
	return os.WriteFile(n.path, b, 0o600)
}

// Notify posts the finding asynchronously if it meets the threshold.
func (n *Notifier) Notify(f scanner.Finding) {
	n.mu.RLock()
	cfg := n.cfg
	n.mu.RUnlock()
	if cfg.WebhookURL == "" {
		return
	}
	if scanner.SeverityRank(f.Severity) > scanner.SeverityRank(cfg.MinSeverity) {
		return
	}
	icon := map[string]string{"high": "🔴", "medium": "🟠", "low": "🔵", "info": "⚪"}[f.Severity]
	loc := f.URL
	if loc == "" {
		loc = f.Host
	}
	msg := icon + " [" + f.Severity + "] " + f.Title + " — " + loc + " (" + f.Check + ")"
	// Send both "text" (Slack) and "content" (Discord) plus structured fields.
	payload, _ := json.Marshal(map[string]any{
		"text": msg, "content": msg,
		"severity": f.Severity, "title": f.Title, "host": f.Host, "url": f.URL, "check": f.Check,
	})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.WebhookURL, bytes.NewReader(payload))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if resp, err := n.http.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
}
