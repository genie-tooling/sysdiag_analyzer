package health

import "testing"

func TestSocketProblem(t *testing.T) {
	cases := []struct {
		active, sub, refused string
		wantBad              bool
	}{
		{"active", "listening", "no", false},  // healthy listening socket
		{"active", "running", "", false},      // running is also fine
		{"inactive", "dead", "no", false},     // inactive socket is allowed
		{"active", "dead", "no", true},        // active but not listening/running
		{"failed", "failed", "no", true},      // unexpected top-level state
		{"active", "listening", "yes", true},  // refusing connections
		{"active", "listening", "true", true}, // dbus-style bool
	}
	for _, c := range cases {
		if bad, _ := socketProblem(c.active, c.sub, c.refused); bad != c.wantBad {
			t.Errorf("socketProblem(%q,%q,%q) = %v, want %v", c.active, c.sub, c.refused, bad, c.wantBad)
		}
	}
}

func TestTimerProblem(t *testing.T) {
	cases := []struct {
		active, sub, result string
		wantBad             bool
	}{
		{"active", "waiting", "success", false}, // healthy waiting timer
		{"active", "running", "", false},        // empty result defaults to success
		{"inactive", "dead", "success", false},  // inactive is allowed
		{"active", "dead", "success", true},     // active but not waiting/running
		{"active", "waiting", "timeout", true},  // last run failed
		{"failed", "failed", "success", true},   // unexpected state
	}
	for _, c := range cases {
		if bad, _ := timerProblem(c.active, c.sub, c.result); bad != c.wantBad {
			t.Errorf("timerProblem(%q,%q,%q) = %v, want %v", c.active, c.sub, c.result, bad, c.wantBad)
		}
	}
}
