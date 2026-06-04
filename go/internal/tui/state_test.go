package tui

import (
	"math"
	"testing"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

func pi(v int64) *int64 { return &v }

const mib = 1024 * 1024

func TestStateCPUPctAndIORate(t *testing.T) {
	s := NewState()
	s.Update([]types.UnitResourceUsage{{Name: "a", CPUUsageNsec: pi(0), IOReadBytes: pi(0)}}, 0.0)
	// 1s later: +0.5s CPU (5e8 ns) -> 50%; +1 MiB read -> 1 MiB/s.
	d := s.Update([]types.UnitResourceUsage{{Name: "a", CPUUsageNsec: pi(500_000_000), IOReadBytes: pi(mib)}}, 1.0)["a"]
	if d.CPUPct == nil || math.Abs(*d.CPUPct-50) > 1e-6 {
		t.Fatalf("cpu%%: got %v want 50", d.CPUPct)
	}
	if d.IOReadRate == nil || math.Abs(*d.IOReadRate-mib) > 1e-6 {
		t.Fatalf("io read rate: got %v want %d", d.IOReadRate, mib)
	}
}

func TestStateLeakFlagAndReset(t *testing.T) {
	s := NewState()
	var d map[string]Derived
	for i := 0; i < s.window; i++ {
		d = s.Update([]types.UnitResourceUsage{{Name: "leak", MemoryAnonBytes: pi(int64(100*mib + i*50*mib))}}, float64(i))
	}
	if !d["leak"].Leaking {
		t.Fatal("expected leaking=true on steady anon climb")
	}
	d = s.Update([]types.UnitResourceUsage{{Name: "leak", MemoryAnonBytes: pi(100 * mib)}}, float64(s.window))
	if d["leak"].Leaking {
		t.Fatal("a drop (restart) should clear the leak flag")
	}
}

func TestStateNoLeakWhenFlat(t *testing.T) {
	s := NewState()
	var d map[string]Derived
	for i := 0; i < s.window; i++ {
		d = s.Update([]types.UnitResourceUsage{{Name: "flat", MemoryAnonBytes: pi(500 * mib)}}, float64(i))
	}
	if d["flat"].Leaking {
		t.Fatal("flat anon must not be flagged as a leak")
	}
}

func TestNetRate(t *testing.T) {
	s := NewState()
	if up, down := s.NetRate(&types.SystemResourceUsage{NetIOSentBytes: pi(0), NetIORecvBytes: pi(0)}, 0); up != nil || down != nil {
		t.Fatal("first sample should yield no rate")
	}
	up, down := s.NetRate(&types.SystemResourceUsage{NetIOSentBytes: pi(1000), NetIORecvBytes: pi(2000)}, 1)
	if up == nil || *up != 1000 || down == nil || *down != 2000 {
		t.Fatalf("net rate: up=%v down=%v want 1000/2000", up, down)
	}
}

func TestSortUsagesByLimit(t *testing.T) {
	units := []types.UnitResourceUsage{
		{Name: "a", MemoryCurrentByte: pi(100), MemoryMaxBytes: pi(1000)}, // 10%
		{Name: "b", MemoryCurrentByte: pi(900), MemoryMaxBytes: pi(1000)}, // 90%
		{Name: "c", MemoryCurrentByte: pi(5000)},                          // no limit -> last
	}
	SortUsages(units, "limit")
	if units[0].Name != "b" || units[len(units)-1].Name != "c" {
		t.Fatalf("limit sort order wrong: %s..%s", units[0].Name, units[len(units)-1].Name)
	}
}
