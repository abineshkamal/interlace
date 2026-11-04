package scanner

import (
	"net/http"
	"testing"

	"interlace/internal/model"
)

func findingChecks(fs []Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.Check] = true
	}
	return m
}

func TestPassiveSecurityHeaders(t *testing.T) {
	f := &model.Flow{
		Scheme: "https", StatusCode: 200, ContentType: "text/html",
		RespHeaders: http.Header{}, // nothing set
	}
	got := findingChecks(Scan(f))
	for _, want := range []string{"missing-hsts", "missing-csp", "missing-xfo", "missing-nosniff"} {
		if !got[want] {
			t.Errorf("expected %s on a bare HTML response", want)
		}
	}
}

func TestPassiveSecretAndJWT(t *testing.T) {
	jwtNone := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
	f := &model.Flow{
		Scheme: "https", StatusCode: 200, ContentType: "application/json",
		RespHeaders: http.Header{"Content-Type": {"application/json"}},
		RespBody:    []byte(`{"k":"AKIAIOSFODNN7EXAMPLE","t":"` + jwtNone + `"}`),
	}
	got := findingChecks(Scan(f))
	if !got["exposed-secret"] {
		t.Error("expected exposed-secret for AWS key")
	}
	if !got["jwt-alg-none"] {
		t.Error("expected jwt-alg-none")
	}
}

func TestPassiveCORSReflection(t *testing.T) {
	f := &model.Flow{
		Scheme: "https", StatusCode: 200,
		ReqHeaders: http.Header{"Origin": {"https://evil.example"}},
		RespHeaders: http.Header{
			"Access-Control-Allow-Origin":      {"https://evil.example"},
			"Access-Control-Allow-Credentials": {"true"},
		},
	}
	got := findingChecks(Scan(f))
	if !got["cors-origin-reflection"] {
		t.Error("expected cors-origin-reflection")
	}
}

func TestPassiveNoFalsePositiveOnCleanResponse(t *testing.T) {
	f := &model.Flow{
		Scheme: "https", StatusCode: 200, ContentType: "application/json",
		RespHeaders: http.Header{
			"Strict-Transport-Security": {"max-age=63072000"},
			"X-Content-Type-Options":    {"nosniff"},
			"Content-Type":              {"application/json"},
		},
		RespBody: []byte(`{"ok":true}`),
	}
	// A clean JSON API response should not raise HTML-only header findings.
	got := findingChecks(Scan(f))
	if got["missing-csp"] || got["missing-xfo"] {
		t.Error("HTML-only checks should not fire on a JSON response")
	}
}
