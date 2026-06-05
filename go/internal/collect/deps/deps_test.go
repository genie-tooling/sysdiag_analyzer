package deps

import "testing"

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestFindCyclesDetectsCycle(t *testing.T) {
	g := map[string][]string{
		"a.service": {"b.service"},
		"b.service": {"c.service"},
		"c.service": {"a.service"},
		"d.service": {"a.service"}, // feeds into the cycle but isn't part of it
	}
	cycles := findCycles(g)
	found := false
	for _, c := range cycles {
		if contains(c, "a.service") && contains(c, "b.service") && contains(c, "c.service") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a->b->c cycle, got %v", cycles)
	}
}

func TestFindCyclesNone(t *testing.T) {
	g := map[string][]string{
		"a.service": {"b.service"},
		"b.service": {"c.service"},
		"c.service": {},
	}
	if cycles := findCycles(g); len(cycles) != 0 {
		t.Fatalf("expected no cycles, got %v", cycles)
	}
}

func TestIsDepProblematic(t *testing.T) {
	cases := []struct {
		typ, load, active, sub string
		want                   bool
	}{
		{"Requires", "loaded", "active", "running", false}, // healthy strong dep
		{"Requires", "loaded", "failed", "failed", true},   // failed strong dep
		{"Requires", "not-found", "", "", true},            // missing strong dep
		{"Requires", "loaded", "inactive", "dead", true},   // inactive strong dep
		{"BindsTo", "loaded", "inactive", "dead", true},    // other strong type
		{"Wants", "loaded", "inactive", "dead", false},     // weak: inactive is fine
		{"Wants", "loaded", "failed", "failed", true},      // weak: only failure counts
		{"After", "loaded", "failed", "failed", false},     // ordering-only, never flagged
		{"Before", "not-found", "", "", false},             // ordering-only
	}
	for _, c := range cases {
		if got := isDepProblematic(c.typ, c.load, c.active, c.sub); got != c.want {
			t.Errorf("isDepProblematic(%q,%q,%q,%q) = %v, want %v", c.typ, c.load, c.active, c.sub, got, c.want)
		}
	}
}

func TestDepMapFromProps(t *testing.T) {
	kv := map[string]string{
		"Requires": "a.service b.service",
		"Wants":    "b.service c.service", // b already seen as Requires -> keeps Requires
		"After":    "d.target",
	}
	m := depMapFromProps(kv)
	if m["a.service"] != "Requires" || m["c.service"] != "Wants" || m["d.target"] != "After" {
		t.Fatalf("unexpected dep map: %v", m)
	}
	if m["b.service"] != "Requires" {
		t.Errorf("b.service should keep the stronger Requires type, got %q", m["b.service"])
	}
}
