// Package ai provides optional AI-assisted triage of findings via the Anthropic
// Messages API. It uses a lightweight raw-HTTP call (no SDK dependency) so the
// core tool stays a single lean binary. The user supplies their own API key.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	endpoint       = "https://api.anthropic.com/v1/messages"
	apiVersion     = "2023-06-01"
	defaultModel   = "claude-opus-5-5"
	requestTimeout = 90 * time.Second
)

// Config holds the API key and model. The key may also come from the
// ANTHROPIC_API_KEY environment variable.
type Config struct {
	APIKey string `json:"apiKey"`
	Model  string `json:"model"`
}

// Store persists AI config to disk and performs triage calls.
type Store struct {
	mu   sync.RWMutex
	cfg  Config
	path string
	http *http.Client
}

// Load reads the AI config from path (falling back to env for the key).
func Load(path string) *Store {
	s := &Store{path: path, http: &http.Client{Timeout: requestTimeout}}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &s.cfg)
	}
	if s.cfg.Model == "" {
		s.cfg.Model = defaultModel
	}
	return s
}

// SetConfig updates and persists the config (an empty key clears it).
func (s *Store) SetConfig(apiKey, model string) error {
	s.mu.Lock()
	s.cfg.APIKey = strings.TrimSpace(apiKey)
	if model != "" {
		s.cfg.Model = model
	}
	snap := s.cfg
	s.mu.Unlock()
	b, _ := json.MarshalIndent(snap, "", "  ")
	return os.WriteFile(s.path, b, 0o600)
}

// Model returns the configured model.
func (s *Store) Model() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg.Model == "" {
		return defaultModel
	}
	return s.cfg.Model
}

func (s *Store) apiKey() string {
	s.mu.RLock()
	k := s.cfg.APIKey
	s.mu.RUnlock()
	if k == "" {
		k = os.Getenv("ANTHROPIC_API_KEY")
	}
	return k
}

// Configured reports whether an API key is available.
func (s *Store) Configured() bool { return s.apiKey() != "" }

const systemPrompt = "You are a senior application security engineer reviewing a single finding from an automated web application security scanner (Interlace). Be precise, practical and honest about uncertainty."

// Triage sends the finding context to Claude and returns a markdown analysis.
func (s *Store) Triage(ctx context.Context, userPrompt string) (string, error) {
	key := s.apiKey()
	if key == "" {
		return "", fmt.Errorf("no API key configured (set it in AI settings or ANTHROPIC_API_KEY)")
	}
	reqBody := map[string]any{
		"model":      s.Model(),
		"max_tokens": 1024,
		"system":     systemPrompt,
		"messages": []map[string]any{
			{"role": "user", "content": userPrompt},
		},
	}
	buf, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", apiVersion)
	req.Header.Set("content-type", "application/json")

	resp, err := s.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))

	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		msg := e.Error.Message
		if msg == "" {
			msg = strings.TrimSpace(string(body))
		}
		return "", fmt.Errorf("API error (%d): %s", resp.StatusCode, msg)
	}

	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	if out.StopReason == "refusal" {
		return "", fmt.Errorf("the model declined to analyze this request")
	}
	var sb strings.Builder
	for _, c := range out.Content {
		if c.Type == "text" {
			sb.WriteString(c.Text)
		}
	}
	text := strings.TrimSpace(sb.String())
	if text == "" {
		return "", fmt.Errorf("empty response")
	}
	return text, nil
}
