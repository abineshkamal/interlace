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

func TestPassiveDisclosureChecks(t *testing.T) {
	cases := []struct {
		name, scheme, ctype string
		body                string
		want                string
	}{
		{"php-error", "https", "text/html", `<b>Fatal error</b>: Uncaught Error in /var/www/app.php`, "error-disclosure"},
		{"python-trace", "https", "text/html", "Traceback (most recent call last):\n  File \"/app/x.py\", line 10", "error-disclosure"},
		{"oracle-error", "https", "application/json", `{"err":"ORA-01756: quoted string not properly terminated"}`, "error-disclosure"},
		{"dir-listing", "https", "text/html", `<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1>`, "directory-listing"},
		{"pw-over-http", "http", "text/html", `<form><input type="password" name="p"></form>`, "password-over-http"},
		{"private-ip", "https", "text/html", `<p>backend host 10.4.12.9 responded</p>`, "private-ip-disclosure"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &model.Flow{
				Scheme: c.scheme, StatusCode: 200, ContentType: c.ctype,
				RespHeaders: http.Header{"Content-Type": {c.ctype}},
				RespBody:    []byte(c.body),
			}
			if !findingChecks(Scan(f))[c.want] {
				t.Errorf("expected %s for %s", c.want, c.name)
			}
		})
	}
	// Negative: a clean HTML page must not trigger the new checks.
	clean := &model.Flow{Scheme: "https", StatusCode: 200, ContentType: "text/html",
		RespHeaders: http.Header{"Content-Type": {"text/html"}},
		RespBody:    []byte(`<html><body><h1>Welcome</h1><p>All good here.</p></body></html>`)}
	got := findingChecks(Scan(clean))
	for _, c := range []string{"error-disclosure", "directory-listing", "password-over-http", "private-ip-disclosure"} {
		if got[c] {
			t.Errorf("false positive: %s on a clean page", c)
		}
	}
}
