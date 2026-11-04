package fuzzer

import "testing"

func TestParseTemplate(t *testing.T) {
	segs, base, err := parseTemplate("GET /a?x=§val§&y=§two§ HTTP/1.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(base) != 2 || base[0] != "val" || base[1] != "two" {
		t.Fatalf("base = %v, want [val two]", base)
	}
	if got := render(segs, []string{"A", "B"}); got != "GET /a?x=A&y=B HTTP/1.1" {
		t.Fatalf("render = %q", got)
	}
}

func TestParseTemplateUnbalanced(t *testing.T) {
	if _, _, err := parseTemplate("GET /a?x=§val HTTP/1.1"); err == nil {
		t.Fatal("expected error for unbalanced markers")
	}
}

func TestAssignmentsCounts(t *testing.T) {
	base := []string{"a", "b"}

	// Sniper: 2 positions * 3 payloads = 6.
	out, _, err := assignments(Config{Attack: Sniper, Payloads: [][]string{{"1", "2", "3"}}}, base, 2)
	if err != nil || len(out) != 6 {
		t.Fatalf("sniper: len=%d err=%v, want 6", len(out), err)
	}

	// Pitchfork: min(len) = 2.
	out, _, err = assignments(Config{Attack: Pitchfork, Payloads: [][]string{{"1", "2", "3"}, {"x", "y"}}}, base, 2)
	if err != nil || len(out) != 2 {
		t.Fatalf("pitchfork: len=%d err=%v, want 2", len(out), err)
	}

	// Cluster bomb: 3 * 2 = 6.
	out, _, err = assignments(Config{Attack: ClusterBomb, Payloads: [][]string{{"1", "2", "3"}, {"x", "y"}}}, base, 2)
	if err != nil || len(out) != 6 {
		t.Fatalf("clusterbomb: len=%d err=%v, want 6", len(out), err)
	}
}
