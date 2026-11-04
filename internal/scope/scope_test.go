package scope

import (
	"path/filepath"
	"testing"
)

func TestInScope(t *testing.T) {
	s := Load(filepath.Join(t.TempDir(), "scope.json"))

	// Fail-closed: nothing in scope until configured.
	if s.InScope("example.com") {
		t.Fatal("empty scope should be fail-closed")
	}

	if err := s.Set([]string{"example.com", "*.test.com"}, []string{"admin.test.com"}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"example.com:443", true}, // port stripped
		{"a.test.com", true},
		{"deep.a.test.com", true},
		{"test.com", true},          // *.test.com matches bare domain
		{"admin.test.com", false},   // excluded
		{"notexample.com", false},   // not a suffix match
		{"other.com", false},
	}
	for _, c := range cases {
		if got := s.InScope(c.host); got != c.want {
			t.Errorf("InScope(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestScopePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.json")
	s1 := Load(path)
	_ = s1.Set([]string{"a.com"}, nil)

	s2 := Load(path)
	if !s2.InScope("a.com") {
		t.Fatal("scope did not persist across reload")
	}
}
