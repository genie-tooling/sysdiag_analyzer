package resources

import "testing"

func TestParseIOStatSumsDevices(t *testing.T) {
	// cgroup v2 io.stat: one major:minor line per device; counters summed.
	r, w := ParseIOStat("8:0 rbytes=100 wbytes=200 rios=1 wios=2\n259:0 rbytes=50 wbytes=25\n")
	if r == nil || *r != 150 || w == nil || *w != 225 {
		t.Fatalf("io.stat: got r=%v w=%v want 150/225", r, w)
	}
	if r2, w2 := ParseIOStat(""); r2 != nil || w2 != nil {
		t.Fatal("empty io.stat should be nil/nil")
	}
}

func TestParseMemoryInt(t *testing.T) {
	if ParseMemoryInt("max") != nil {
		t.Fatal(`"max" must parse to nil (unlimited)`)
	}
	if v := ParseMemoryInt("1048576"); v == nil || *v != 1048576 {
		t.Fatalf("got %v want 1048576", v)
	}
	if ParseMemoryInt("") != nil {
		t.Fatal("empty -> nil")
	}
}

func TestParseMemoryStat(t *testing.T) {
	s := ParseMemoryStat("anon 1024\nfile 2048\nslab 9\n")
	if s["anon"] != 1024 || s["file"] != 2048 {
		t.Fatalf("got %v", s)
	}
}

func TestParseCPUStatToNsec(t *testing.T) {
	v := ParseCPUStat("usage_usec 1000\nuser_usec 600\nsystem_usec 400\n")
	if v == nil || *v != 1_000_000 { // usec * 1000
		t.Fatalf("got %v want 1000000", v)
	}
}

func TestParseTasks(t *testing.T) {
	if v := ParseTasks("10\n20\n30\n"); v == nil || *v != 3 {
		t.Fatalf("got %v want 3", v)
	}
}
