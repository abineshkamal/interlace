package scanner

import "testing"

func TestParseRequestInsertionPoints(t *testing.T) {
	raw := "POST /search?q=hi HTTP/1.1\r\nHost: x\r\nCookie: sid=1; theme=dark\r\nContent-Type: application/json\r\n\r\n{\"name\":\"bob\",\"n\":5}"
	req, err := parseRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	pts := req.insertionPoints()
	kinds := map[string]bool{}
	for _, p := range pts {
		kinds[p.in+":"+p.name] = true
	}
	for _, want := range []string{"query:q", "cookie:sid", "cookie:theme", "json:name"} {
		if !kinds[want] {
			t.Errorf("missing insertion point %q (got %v)", want, kinds)
		}
	}
	// "n" is a number, not a string field, so it should not be an insertion point.
	if kinds["json:n"] {
		t.Error("numeric JSON field should not be an insertion point")
	}
}

func TestRenderCookieInjection(t *testing.T) {
	raw := "GET /a HTTP/1.1\r\nHost: x\r\nCookie: sid=1; theme=dark\r\n\r\n"
	req, _ := parseRequest(raw)
	out := req.render(&point{in: "cookie", name: "sid"}, "INJECTED")
	if want := "Cookie: sid=INJECTED; theme=dark"; !contains(out, want) {
		t.Fatalf("render did not inject cookie; got:\n%s", out)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
