// Package leak detects sustained anon-memory growth (memory leaks) over history.
// Pure Go port of ml_baseline.detect_memory_leaks.
package leak

import (
	"math"
	"sort"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/features"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

const (
	MinSamples         = 6
	MinSlopeBytesPerHr = 10 * 1024 * 1024 // 10 MiB/hour
	MinR2              = 0.8
	resetDropFrac      = 0.7 // anon dropping below 70% of prior = restart
)

type point struct {
	ts, anon float64
}

func linearFit(xs, ys []float64) (slope, r2 float64) {
	n := float64(len(xs))
	var mx, my float64
	for i := range xs {
		mx += xs[i]
		my += ys[i]
	}
	mx /= n
	my /= n
	var sxx, sxy, sstot float64
	for i := range xs {
		sxx += (xs[i] - mx) * (xs[i] - mx)
		sxy += (xs[i] - mx) * (ys[i] - my)
		sstot += (ys[i] - my) * (ys[i] - my)
	}
	if sxx == 0 {
		return 0, 0
	}
	slope = sxy / sxx
	if sstot == 0 {
		return slope, 1.0
	}
	intercept := my - slope*mx
	var ssres float64
	for i := range xs {
		pred := slope*xs[i] + intercept
		ssres += (ys[i] - pred) * (ys[i] - pred)
	}
	return slope, 1.0 - ssres/sstot
}

// Detect returns suspected leaks (most severe first) and the count of units analyzed.
func Detect(feats []features.Feature, only map[string]bool) ([]types.MemoryLeakInfo, int) {
	byUnit := map[string][]point{}
	for _, f := range feats {
		if only != nil && !only[f.Unit] {
			continue
		}
		if f.MemAnon == nil {
			continue
		}
		byUnit[f.Unit] = append(byUnit[f.Unit], point{ts: f.TS, anon: float64(*f.MemAnon)})
	}

	var leaks []types.MemoryLeakInfo
	analyzed := 0
	for unit, pts := range byUnit {
		sort.Slice(pts, func(i, j int) bool { return pts[i].ts < pts[j].ts })
		start := 0
		for i := 1; i < len(pts); i++ {
			if pts[i].anon < pts[i-1].anon*resetDropFrac {
				start = i
			}
		}
		seg := pts[start:]
		if len(seg) < MinSamples {
			continue
		}
		analyzed++
		t0 := seg[0].ts
		xs := make([]float64, len(seg))
		ys := make([]float64, len(seg))
		for i, p := range seg {
			xs[i] = p.ts - t0
			ys[i] = p.anon
		}
		slope, r2 := linearFit(xs, ys)
		slopePerHour := slope * 3600.0
		growth := ys[len(ys)-1] - ys[0]
		if slopePerHour >= MinSlopeBytesPerHr && r2 >= MinR2 && growth > 0 {
			leaks = append(leaks, types.MemoryLeakInfo{
				UnitName:          unit,
				SlopeBytesPerHour: slopePerHour,
				GrowthBytes:       int64(growth),
				RSquared:          math.Round(r2*1000) / 1000,
				Samples:           len(seg),
			})
		}
	}
	sort.Slice(leaks, func(i, j int) bool { return leaks[i].SlopeBytesPerHour > leaks[j].SlopeBytesPerHour })
	return leaks, analyzed
}
