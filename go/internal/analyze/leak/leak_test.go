package leak

import (
	"testing"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/features"
)

func pi(v int64) *int64 { return &v }

const mib = 1024 * 1024

func anonFeat(unit string, hour int, anon int64) features.Feature {
	return features.Feature{Unit: unit, TS: float64(hour * 3600), MemAnon: pi(anon)}
}

func TestLeakLinearGrowth(t *testing.T) {
	var feats []features.Feature
	for i := 0; i < 8; i++ {
		feats = append(feats, anonFeat("leaky.service", i, int64(100+i*100)*mib)) // +100 MiB/h
	}
	leaks, analyzed := Detect(feats, nil)
	if analyzed != 1 || len(leaks) != 1 {
		t.Fatalf("analyzed=%d leaks=%d", analyzed, len(leaks))
	}
	if leaks[0].SlopeBytesPerHour < 90*mib || leaks[0].RSquared < 0.99 {
		t.Fatalf("slope=%.0f r2=%.3f", leaks[0].SlopeBytesPerHour, leaks[0].RSquared)
	}
}

func TestLeakFlatIgnored(t *testing.T) {
	var feats []features.Feature
	for i := 0; i < 8; i++ {
		feats = append(feats, anonFeat("flat.service", i, 500*mib))
	}
	leaks, analyzed := Detect(feats, nil)
	if len(leaks) != 0 || analyzed != 1 {
		t.Fatalf("flat: leaks=%d analyzed=%d", len(leaks), analyzed)
	}
}

func TestLeakInsufficientSamples(t *testing.T) {
	var feats []features.Feature
	for i := 0; i < 4; i++ {
		feats = append(feats, anonFeat("svc", i, int64(100+i*100)*mib))
	}
	leaks, analyzed := Detect(feats, nil)
	if len(leaks) != 0 || analyzed != 0 {
		t.Fatalf("insufficient: leaks=%d analyzed=%d", len(leaks), analyzed)
	}
}
