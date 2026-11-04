// Package ai provides optional, provider-agnostic AI-assisted triage of
// findings. It supports two request formats that between them cover virtually
// every AI service: Anthropic's Messages API and the OpenAI-compatible Chat
// Completions API (OpenAI, Azure, Google Gemini's OpenAI endpoint, Groq,
// OpenRouter, Together, Mistral, DeepSeek, and local runtimes like Ollama,
// LM Studio and vLLM via a custom base URL). Raw HTTP, no SDK dependency.
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

// Providers.
const (
	ProviderAnthropic = "anthropic"
	ProviderOpenAI    = "openai" // OpenAI-compatible Chat Completions
)

const (
	anthropicDefaultBase = "https://api.anthropic.com"
	openaiDefaultBase    = "https://api.openai.com/v1"
	anthropicVersion     = "2023-06-01"
	requestTimeout       = 120 * time.Second
)

// Config describes the AI backend.
type Config struct {
	Provider string `json:"provider"` // "anthropic" | "openai"
	BaseURL  string `json:"baseUrl"`  // optional override (required for local/custom endpoints)
	APIKey   string `json:"apiKey"`
	Model    string `json:"model"`
}

// Store persists config and performs triage calls.
type Store struct {
	mu   sync.RWMutex
	cfg  Config
	path string
	http *http.Client
}

// Load reads AI config from path (API key also honored from env vars).
func Load(path string) *Store {
	s := &Store{path: path, http: &http.Client{Timeout: requestTimeout}}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &s.cfg)
	}
	if s.cfg.Provider == "" {
		s.cfg.Provider = ProviderAnthropic
	}
	return s
}

// SetConfig updates and persists the config. An empty apiKey keeps the current key.
func (s *Store) SetConfig(c Config) error {
	s.mu.Lock()
	if c.Provider != "" {
		s.cfg.Provider = c.Provider
	}
	s.cfg.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	s.cfg.Model = strings.TrimSpace(c.Model)
	if strings.TrimSpace(c.APIKey) != "" {
		s.cfg.APIKey = strings.TrimSpace(c.APIKey)
	}
	snap := s.cfg
	s.mu.Unlock()
	b, _ := json.MarshalIndent(snap, "", "  ")
	return os.WriteFile(s.path, b, 0o600)
}

// Public returns the non-secret config for the UI.
func (s *Store) Public() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]any{
		"provider":   s.cfg.Provider,
		"baseUrl":    s.cfg.BaseURL,
		"model":      s.cfg.Model,
		"configured": s.configuredLocked(),
	}
}

func (s *Store) apiKey() string {
	s.mu.RLock()
	k, provider := s.cfg.APIKey, s.cfg.Provider
	s.mu.RUnlock()
	if k != "" {
		return k
	}
	if provider == ProviderAnthropic {
		return os.Getenv("ANTHROPIC_API_KEY")
	}
	return os.Getenv("OPENAI_API_KEY")
}

func (s *Store) configuredLocked() bool {
	if s.cfg.APIKey != "" {
		return true
	}
	// A custom (e.g. local) base URL counts as configured even without a key.
	if s.cfg.BaseURL != "" &&
		!strings.Contains(s.cfg.BaseURL, "api.openai.com") &&
		!strings.Contains(s.cfg.BaseURL, "api.anthropic.com") {
		return true
	}
	if s.cfg.Provider == ProviderAnthropic {
		return os.Getenv("ANTHROPIC_API_KEY") != ""
	}
	return os.Getenv("OPENAI_API_KEY") != ""
}

// Configured reports whether triage can run.
func (s *Store) Configured() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configuredLocked()
}

const systemPrompt = "You are a senior application security engineer reviewing a single finding from an automated web application security scanner (Interlace). Be precise, practical and honest about uncertainty."

// Triage sends the finding context to the configured model and returns markdown.
func (s *Store) Triage(ctx context.Context, userPrompt string) (string, error) {
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()

	if cfg.Provider == ProviderAnthropic {
		return s.callAnthropic(ctx, cfg, userPrompt)
	}
	return s.callOpenAI(ctx, cfg, userPrompt)
}

func (s *Store) callAnthropic(ctx context.Context, cfg Config, userPrompt string) (string, error) {
	key := s.apiKey()
	if key == "" {
		return "", fmt.Errorf("no API key configured")
	}
	base := cfg.BaseURL
	if base == "" {
		base = anthropicDefaultBase
	}
	model := cfg.Model
	if model == "" {
		model = "claude-opus-5-5"
	}
	reqBody := map[string]any{
		"model":      model,
		"max_tokens": 1024,
		"system":     systemPrompt,
		"messages":   []map[string]any{{"role": "user", "content": userPrompt}},
	}
	req, err := s.newJSONRequest(ctx, base+"/v1/messages", reqBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", anthropicVersion)

	body, err := s.do(req)
	if err != nil {
		return "", err
	}
	var out struct {
		Content []struct {
			Type, Text string
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
	return finalize(sb.String())
}

func (s *Store) callOpenAI(ctx context.Context, cfg Config, userPrompt string) (string, error) {
	base := cfg.BaseURL
	if base == "" {
		base = openaiDefaultBase
	}
	model := cfg.Model
	if model == "" {
		model = "gpt-4o-mini"
	}
	reqBody := map[string]any{
		"model": model,
		"messages": []map[string]any{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userPrompt},
		},
		"max_tokens": 1024,
	}
	req, err := s.newJSONRequest(ctx, base+"/chat/completions", reqBody)
	if err != nil {
		return "", err
	}
	if key := s.apiKey(); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}

	body, err := s.do(req)
	if err != nil {
		return "", err
	}
	var out struct {
		Choices []struct {
			Message struct{ Content string } `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("empty response")
	}
	return finalize(out.Choices[0].Message.Content)
}

func (s *Store) newJSONRequest(ctx context.Context, url string, body any) (*http.Request, error) {
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	return req, nil
}

func (s *Store) do(req *http.Request) ([]byte, error) {
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error struct{ Message string } `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		msg := e.Error.Message
		if msg == "" {
			msg = strings.TrimSpace(string(body))
			if len(msg) > 300 {
				msg = msg[:300]
			}
		}
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, msg)
	}
	return body, nil
}

func finalize(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("empty response")
	}
	return s, nil
}
