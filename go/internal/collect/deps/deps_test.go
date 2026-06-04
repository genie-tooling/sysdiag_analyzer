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
