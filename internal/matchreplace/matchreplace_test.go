package matchreplace

import (
	"net/http"
	"path/filepath"
	"testing"
)

func TestApplyBody(t *testing.T) {
	e := Load(filepath.Join(t.TempDir(), "mr.json"))
	_ = e.Set([]Rule{{Enabled: true, Part: RespBody, Match: "foo", Replace: "bar"}})
	out := e.ApplyBody(RespBody, "example.com", []byte("a foo b foo"))
	if string(out) != "a bar b bar" {
		t.Fatalf("ApplyBody = %q", out)
	}
}

func TestApplyHeadersAppend(t *testing.T) {
	e := Load(filepath.Join(t.TempDir(), "mr.json"))
	_ = e.Set([]Rule{{Enabled: true, Part: ReqHeader, Match: "", Replace: "X-Test: 1"}})
	h := http.Header{"Existing": {"v"}}
	e.ApplyHeaders(ReqHeader, "example.com", h)
	if h.Get("X-Test") != "1" {
		t.Fatalf("expected appended header; got %v", h)
	}
}

func TestHostFilter(t *testing.T) {
	e := Load(filepath.Join(t.TempDir(), "mr.json"))
	_ = e.Set([]Rule{{Enabled: true, Part: RespBody, Match: "a", Replace: "b", Host: "only.com"}})
	// Non-matching host: unchanged.
	if got := e.ApplyBody(RespBody, "other.com", []byte("a")); string(got) != "a" {
		t.Fatalf("host filter should skip; got %q", got)
	}
	// Matching host: applied.
	if got := e.ApplyBody(RespBody, "only.com", []byte("a")); string(got) != "b" {
		t.Fatalf("host filter should apply; got %q", got)
	}
}

func TestDisabledRuleNoop(t *testing.T) {
	e := Load(filepath.Join(t.TempDir(), "mr.json"))
	_ = e.Set([]Rule{{Enabled: false, Part: RespBody, Match: "a", Replace: "b"}})
	if e.Enabled() {
		t.Fatal("disabled rule should not mark engine enabled")
	}
}
