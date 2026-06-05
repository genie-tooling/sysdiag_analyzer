package baseline

import (
	"path/filepath"
	"testing"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

func pi(v int64) *int64 { return &v }

const mib = 1024 * 1024

func memUsage(name string, cur int64) []types.UnitResourceUsage {
	return []types.UnitResourceUsage{{Name: name, MemoryCurrentByte: pi(cur)}}
}
func cpuUsage(name string, cpu int64) []types.UnitResourceUsage {
	return []types.UnitResourceUsage{{Name: name, CPUUsageNsec: pi(cpu)}}
}

func TestSpikeFlaggedAfterWarmup(t *testing.T) {
	s := New()
	for i := 0; i < 10; i++ { // warm with mild jitter so variance > 0
		Detect(s, memUsage("u", int64((100+(i%3))*mib)), float64(i*60), "medium", false, 0.3, 8, nil)
	}
	a := Detect(s, memUsage("u", 5*1024*mib), float64(10*60), "medium", false, 0.3, 8, nil)
	if len(a) != 1 {
		t.Fatalf("want 1 anomaly, got %d", len(a))
	}
	if _, ok := a[0].ContributingMetrics["mem_current_bytes"]; !ok {
		t.Fatalf("expected mem_current_bytes contributor: %v", a[0].ContributingMetrics)
	}
	if a[0].Method != "baseline" {
		t.Fatalf("method = %q", a[0].Method)
	}
}

func TestSlowDriftNotFlagged(t *testing.T) {
	s := New()
	for i := 0; i < 14; i++ { // steady +1 MiB/step ramp — EWMA control chart tolerates drift
		a := Detect(s, memUsage("u", int64((100+i)*mib)), float64(i*60), "medium", false, 0.3, 8, nil)
		if len(a) > 0 {
			t.Fatalf("slow drift flagged at step %d: %v", i, a)
		}
	}
}

func TestWarmupSilent(t *testing.T) {
	s := New()
	for i := 0; i < 7; i++ { // fewer than min_updates=8
		v := int64(100 * mib)
		if i == 6 {
			v = 9 * 1024 * mib // spike while still warming
		}
		if a := Detect(s, memUsage("u", v), float64(i*60), "medium", false, 0.3, 8, nil); len(a) > 0 {
			t.Fatalf("flagged during warmup at step %d", i)
		}
	}
}

func TestCounterResetNotFlagged(t *testing.T) {
	s := New()
	for i := 0; i < 10; i++ { // constant cpu rate
		Detect(s, cpuUsage("u", int64(i)*1_000_000_000), float64(i*60), "medium", false, 0.3, 8, nil)
	}
	a := Detect(s, cpuUsage("u", 5e8), float64(10*60), "medium", false, 0.3, 8, nil) // reboot/reset
	for _, an := range a {
		if _, ok := an.ContributingMetrics["cpu_usage_rate"]; ok {
			t.Fatal("counter reset should not be flagged as a rate anomaly")
		}
	}
}

func TestSeasonalBucketSpike(t *testing.T) {
	s := New()
	const base = 1_000_000.0 // fixed hour; +10s increments stay in the same bucket
	for i := 0; i < 10; i++ {
		Detect(s, memUsage("u", int64((100+(i%3))*mib)), base+float64(i*10), "medium", true, 0.3, 8, nil)
	}
	a := Detect(s, memUsage("u", 5*1024*mib), base+float64(10*10), "medium", true, 0.3, 8, nil)
	if len(a) != 1 {
		t.Fatalf("seasonal spike not flagged, got %d", len(a))
	}
}

func TestStoreRoundTripAndPrune(t *testing.T) {
	s := New()
	Detect(s, memUsage("u.service", 100*mib), 1000, "medium", false, 0.3, 8, nil)
	p := filepath.Join(t.TempDir(), "baseline.json")
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	s2 := Load(p)
	if s2.Units["u.service"] == nil {
		t.Fatal("round-trip lost the unit's state")
	}
	s2.Prune(1000+8*24*3600, 7*24*3600) // 8 days later, 7-day max age
	if _, ok := s2.Units["u.service"]; ok {
		t.Fatal("stale unit should have been pruned")
	}
}
