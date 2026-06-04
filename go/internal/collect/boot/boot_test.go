package boot

import "testing"

func TestBootLineCompoundDurations(t *testing.T) {
	line := "Startup finished in 10.951s (firmware) + 3.158s (loader) + 696ms (kernel) + " +
		"24.497s (initrd) + 1min 21.085s (userspace) = 2min 389ms"
	m := bootLineRe.FindStringSubmatch(line)
	if m == nil {
		t.Fatal("compound-duration boot line did not match")
	}
	got := map[string]string{}
	for i, name := range bootLineRe.SubexpNames() {
		if name != "" {
			got[name] = m[i]
		}
	}
	for k, want := range map[string]string{
		"firmware": "10.951s", "kernel": "696ms", "userspace": "1min 21.085s", "total": "2min 389ms",
	} {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
}

func TestBootLineSimple(t *testing.T) {
	m := bootLineRe.FindStringSubmatch("Startup finished in 1.2s (kernel) + 3.4s (userspace) = 4.6s")
	if m == nil {
		t.Fatal("simple boot line did not match")
	}
}
