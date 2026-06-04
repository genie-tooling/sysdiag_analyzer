// Package stats is the default anomaly detector: robust per-(unit,metric)
// modified z-score over recent history. Pure Go port of ml_baseline.py.
package stats

import (
	"math"
	"sort"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/features"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

const (
	minBaseline = 8     // MIN_BASELINE_SAMPLES
	constantZ   = 1.0e6 // sentinel for a constant baseline (JSON-safe, not Inf)
)

var thresholds = map[string]float64{"low": 5.0, "medium": 3.5, "high": 2.5}

func sensitivityThreshold(s string) float64 {
	if t, ok := thresholds[s]; ok {
		return t
	}
	return thresholds["medium"]
}

func medianSorted(xs []float64) float64 {
	n := len(xs)
	if n == 0 {
		return 0
	}
	cp := append([]float64(nil), xs...)
	sort.Float64s(cp)
	if n%2 == 1 {
		return cp[n/2]
	}
	return (cp[n/2-1] + cp[n/2]) / 2
}

func stdev(xs []float64) float64 {
	n := len(xs)
	if n < 2 {
		return 0
	}
	var mean float64
	for _, x := range xs {
		mean += x
	}
	mean /= float64(n)
	var ss float64
	for _, x := range xs {
		ss += (x - mean) * (x - mean)
	}
	return math.Sqrt(ss / float64(n-1))
}

func modifiedZ(current float64, baseline []float64) (float64, bool) {
	if len(baseline) < minBaseline {
		return 0, false
	}
	med := medianSorted(baseline)
	dev := make([]float64, len(baseline))
	for i, x := range baseline {
		dev[i] = math.Abs(x - med)
	}
	if mad := medianSorted(dev); mad > 0 {
		return 0.6745 * (current - med) / mad, true
	}
	if sd := stdev(baseline); sd > 0 {
		return (current - med) / sd, true
	}
	if current == med {
		return 0, true
	}
	return constantZ, true
}

// DetectAnomalies flags units whose latest sample deviates from their own history.
func DetectAnomalies(feats []features.Feature, sensitivity string, only map[string]bool) []types.AnomalyInfo {
	thr := sensitivityThreshold(sensitivity)
	byUnit := map[string][]features.Feature{}
	for _, f := range feats {
		if only != nil && !only[f.Unit] {
			continue
		}
		byUnit[f.Unit] = append(byUnit[f.Unit], f)
	}

	var anomalies []types.AnomalyInfo
	for unit, samples := range byUnit {
		if len(samples) < minBaseline+1 {
			continue
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i].TS < samples[j].TS })

		contributing := map[string]float64{}
		for name, vals := range buildSeries(samples) {
			cur := vals[len(vals)-1]
			if cur == nil {
				continue
			}
			baseline := nonNil(vals[:len(vals)-1])
			if z, ok := modifiedZ(*cur, baseline); ok && z >= thr {
				contributing[name] = math.Round(z*100) / 100
			}
		}
		if len(contributing) > 0 {
			score := 0.0
			for _, z := range contributing {
				if z > score {
					score = z
				}
			}
			anomalies = append(anomalies, types.AnomalyInfo{
				UnitName: unit, Score: score, Method: "statistical", ContributingMetrics: contributing,
			})
		}
	}
	sort.Slice(anomalies, func(i, j int) bool { return anomalies[i].Score > anomalies[j].Score })
	return anomalies
}

// buildSeries: gauges as levels; counters as per-second rates (nil on reset/first).
func buildSeries(samples []features.Feature) map[string][]*float64 {
	gauge := func(get func(features.Feature) *int64) []*float64 {
		out := make([]*float64, len(samples))
		for i, s := range samples {
			if v := get(s); v != nil {
				f := float64(*v)
				out[i] = &f
			}
		}
		return out
	}
	rate := func(get func(features.Feature) *int64) []*float64 {
		out := make([]*float64, len(samples))
		for i := 1; i < len(samples); i++ {
			pv, cv := get(samples[i-1]), get(samples[i])
			dt := samples[i].TS - samples[i-1].TS
			if pv != nil && cv != nil && dt > 0 {
				delta := float64(*cv - *pv)
				if delta >= 0 {
					r := delta / dt
					out[i] = &r
				}
			}
		}
		return out
	}
	return map[string][]*float64{
		"mem_current_bytes": gauge(func(f features.Feature) *int64 { return f.MemCurrent }),
		"tasks_current":     gauge(func(f features.Feature) *int64 { return f.Tasks }),
		"cpu_usage_rate":    rate(func(f features.Feature) *int64 { return f.CPUNsec }),
		"io_read_rate":      rate(func(f features.Feature) *int64 { return f.IORead }),
		"io_write_rate":     rate(func(f features.Feature) *int64 { return f.IOWrite }),
	}
}

func nonNil(vals []*float64) []float64 {
	out := make([]float64, 0, len(vals))
	for _, v := range vals {
		if v != nil {
			out = append(out, *v)
		}
	}
	return out
}
