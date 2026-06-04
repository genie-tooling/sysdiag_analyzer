package stats

import (
	"testing"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/features"
)

func pi(v int64) *int64 { return &v }

const mib = 1024 * 1024

func mkFeat(unit string, i int, memCur int64) features.Feature {
	return features.Feature{Unit: unit, TS: float64(i * 60), MemCurrent: pi(memCur), CPUNsec: pi(int64(i) * 1_000_000_000)}
}

func TestDetectMemorySpike(t *testing.T) {
	var feats []features.Feature
	n := minBaseline + 5
	for i := 0; i < n; i++ {
		feats = append(feats, mkFeat("spike.service", i, int64(100+(i%7))*mib))
	}
	feats[len(feats)-1].MemCurrent = pi(5 * 1024 * mib) // 5 GiB spike
	a := DetectAnomalies(feats, "medium", nil)
	if len(a) != 1 {
		t.Fatalf("want 1 anomaly, got %d", len(a))
	}
	if _, ok := a[0].ContributingMetrics["mem_current_bytes"]; !ok {
		t.Fatalf("expected mem_current_bytes contributor, got %v", a[0].ContributingMetrics)
	}
	if a[0].Method != "statistical" {
		t.Fatalf("method = %q", a[0].Method)
	}
}

func TestDetectSteadyNoAnomaly(t *testing.T) {
	var feats []features.Feature
	for i := 0; i < minBaseline+5; i++ {
		feats = append(feats, mkFeat("flat.service", i, 500*mib))
	}
	if a := DetectAnomalies(feats, "medium", nil); len(a) != 0 {
		t.Fatalf("steady series should not flag, got %d", len(a))
	}
}

func TestColdStartSilent(t *testing.T) {
	var feats []features.Feature
	for i := 0; i < minBaseline; i++ { // only minBaseline (< minBaseline+1) samples
		feats = append(feats, mkFeat("new.service", i, int64(100+i)*mib))
	}
	feats[len(feats)-1].MemCurrent = pi(9 * 1024 * mib)
	if a := DetectAnomalies(feats, "medium", nil); len(a) != 0 {
		t.Fatalf("cold start should be silent, got %d", len(a))
	}
}
