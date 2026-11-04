package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestApplyGlobalAndHostRules(t *testing.T) {
	s := Load(filepath.Join(t.TempDir(), "s.json"))
	if err := s.Set([]Header{{Name: "Authorization", Value: "Bearer global"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetHostRules([]HostRule{
		{Pattern: "api.example.com", Headers: []Header{{Name: "X-Api-Key", Value: "k1"}}},
		{Pattern: ".internal", Headers: []Header{{Name: "X-Env", Value: "corp"}}},
	}); err != nil {
		t.Fatal(err)
	}

	h := http.Header{}
	s.Apply("api.example.com:443", h)
	if h.Get("Authorization") != "Bearer global" {
		t.Errorf("global header not applied: %q", h.Get("Authorization"))
	}
	if h.Get("X-Api-Key") != "k1" {
		t.Errorf("host rule not applied: %q", h.Get("X-Api-Key"))
	}
	if h.Get("X-Env") != "" {
		t.Errorf("unrelated host rule leaked: %q", h.Get("X-Env"))
	}

	h2 := http.Header{}
	s.Apply("db.internal", h2)
	if h2.Get("X-Env") != "corp" {
		t.Errorf("dot-suffix host rule not applied: %q", h2.Get("X-Env"))
	}
	if h2.Get("X-Api-Key") != "" {
		t.Errorf("exact host rule leaked to other host: %q", h2.Get("X-Api-Key"))
	}
}

func TestCSRFTokenFetchAndCache(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write([]byte(`<form><input name="csrf" value="TOKEN-ABC123"></form>`))
	}))
	defer srv.Close()

	s := Load(filepath.Join(t.TempDir(), "s.json"))
	if err := s.SetCSRF(CSRFConfig{
		Enabled: true, URL: srv.URL, Inject: "header", Name: "X-CSRF-Token",
		Regex: `name="csrf" value="([^"]+)"`,
	}); err != nil {
		t.Fatal(err)
	}

	name, val, inject, ok := s.CSRFToken(context.Background())
	if !ok {
		t.Fatal("expected a CSRF token")
	}
	if name != "X-CSRF-Token" || val != "TOKEN-ABC123" || inject != "header" {
		t.Errorf("unexpected token result: name=%q val=%q inject=%q", name, val, inject)
	}

	// Second call within the TTL must be served from cache (no extra fetch).
	if _, _, _, ok := s.CSRFToken(context.Background()); !ok {
		t.Fatal("expected cached token")
	}
	if h := atomic.LoadInt32(&hits); h != 1 {
		t.Errorf("expected 1 upstream fetch (cached thereafter), got %d", h)
	}
}

func TestCSRFDisabled(t *testing.T) {
	s := Load(filepath.Join(t.TempDir(), "s.json"))
	if _, _, _, ok := s.CSRFToken(context.Background()); ok {
		t.Error("CSRF should be disabled by default")
	}
}

func TestLegacyHeaderArrayLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.json")
	if err := os.WriteFile(path, []byte(`[{"name":"Cookie","value":"sid=1"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := Load(path)
	got := s.Get()
	if len(got) != 1 || got[0].Name != "Cookie" || got[0].Value != "sid=1" {
		t.Errorf("legacy []Header format not loaded: %+v", got)
	}
}
