// Package baseline is an online, adaptive anomaly detector: it learns each
// (unit, metric) baseline as an EWMA control chart (optionally per hour-of-day)
// and flags samples beyond mean + k*sigma. Unlike analyze/stats it is stateful —
// it persists and updates a small baseline across runs rather than recomputing
// from a history window.
package baseline

import (
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

const (
	DefaultAlpha      = 0.3
	DefaultMinUpdates = 8
	constZ            = 1.0e6 // constant-baseline sentinel (JSON-safe, not Inf)
)

var thresholds = map[string]float64{"low": 4.0, "medium": 3.0, "high": 2.5}

func threshold(s string) float64 {
	if t, ok := thresholds[s]; ok {
		return t
	}
	return thresholds["medium"]
}

// ewma holds West's exponentially-weighted mean and variance.
type ewma struct {
	N    int     `json:"n"`
	Mean float64 `json:"mean"`
	Var  float64 `json:"var"`
}

// score returns the one-sided high z-score of x against the current (pre-update)
// baseline and whether the baseline is warm enough to judge.
func (e *ewma) score(x float64, minUpdates int) (float64, bool) {
	if e.N < minUpdates {
		return 0, false
	}
	sd := math.Sqrt(e.Var)
	if sd <= 0 {
		if x == e.Mean {
			return 0, true
		}
		return constZ, true
	}
	return (x - e.Mean) / sd, true
}

func (e *ewma) update(x, alpha float64) {
	if e.N == 0 {
		e.Mean, e.Var, e.N = x, 0, 1
		return
	}
	diff := x - e.Mean
	e.Mean += alpha * diff
	e.Var = (1 - alpha) * (e.Var + alpha*diff*diff)
	e.N++
}

// MetricState is the learned baseline for one (unit, metric).
type MetricState struct {
	Global   ewma             `json:"global"`
	Seasonal map[string]*ewma `json:"seasonal,omitempty"` // hour-of-day "0".."23" -> ewma
	PrevCtr  *float64         `json:"prev_ctr,omitempty"` // last raw counter (rate metrics)
	PrevTS   float64          `json:"prev_ts,omitempty"`
}

// rate derives a per-second rate for counter metrics, updating the stored prev.
// Returns ok=false on the first sample or a counter reset (negative delta).
func (m *MetricState) rate(cur, now float64) (float64, bool) {
	prev, prevTS := m.PrevCtr, m.PrevTS
	v := cur
	m.PrevCtr, m.PrevTS = &v, now
	if prev == nil {
		return 0, false
	}
	dt := now - prevTS
	delta := cur - *prev
	if dt <= 0 || delta < 0 {
		return 0, false
	}
	return delta / dt, true
}

type metricDef struct {
	name    string
	counter bool
	get     func(types.UnitResourceUsage) *int64
}

// Metrics scored: gauges as levels, counters as per-second rates.
var metrics = []metricDef{
	{"mem_current_bytes", false, func(u types.UnitResourceUsage) *int64 { return u.MemoryCurrentByte }},
	{"mem_anon_bytes", false, func(u types.UnitResourceUsage) *int64 { return u.MemoryAnonBytes }},
	{"tasks_current", false, func(u types.UnitResourceUsage) *int64 { return u.TasksCurrent }},
	{"cpu_usage_rate", true, func(u types.UnitResourceUsage) *int64 { return u.CPUUsageNsec }},
	{"io_read_rate", true, func(u types.UnitResourceUsage) *int64 { return u.IOReadBytes }},
	{"io_write_rate", true, func(u types.UnitResourceUsage) *int64 { return u.IOWriteBytes }},
	{"pgmajfault_rate", true, func(u types.UnitResourceUsage) *int64 { return u.MemoryPgMajfault }},
}

func hourOf(epoch float64) string {
	return strconv.Itoa(time.Unix(int64(epoch), 0).UTC().Hour())
}

// Detect scores the current per-unit usage against the learned baseline (then
// updates it with the new sample). now is wall-clock epoch seconds.
func Detect(s *Store, usage []types.UnitResourceUsage, now float64,
	sensitivity string, seasonal bool, alpha float64, minUpdates int, only map[string]bool) []types.AnomalyInfo {
	if alpha <= 0 || alpha >= 1 {
		alpha = DefaultAlpha
	}
	if minUpdates <= 0 {
		minUpdates = DefaultMinUpdates
	}
	k := threshold(sensitivity)
	hour := hourOf(now)

	var anomalies []types.AnomalyInfo
	for _, u := range usage {
		if only != nil && !only[u.Name] {
			continue
		}
		um := s.metric(u.Name)
		s.LastSeen[u.Name] = now
		contributing := map[string]float64{}
		for _, m := range metrics {
			raw := m.get(u)
			if raw == nil {
				continue
			}
			ms := um[m.name]
			if ms == nil {
				ms = &MetricState{}
				um[m.name] = ms
			}
			var value float64
			if m.counter {
				r, ok := ms.rate(float64(*raw), now)
				if !ok {
					continue
				}
				value = r
			} else {
				value = float64(*raw)
			}
			e := &ms.Global
			if seasonal {
				if ms.Seasonal == nil {
					ms.Seasonal = map[string]*ewma{}
				}
				if ms.Seasonal[hour] == nil {
					ms.Seasonal[hour] = &ewma{}
				}
				e = ms.Seasonal[hour]
			}
			if z, warm := e.score(value, minUpdates); warm && z >= k {
				if z != constZ {
					z = math.Round(z*100) / 100
				}
				contributing[m.name] = z
			}
			e.update(value, alpha)
		}
		if len(contributing) > 0 {
			score := 0.0
			for _, z := range contributing {
				if z > score {
					score = z
				}
			}
			anomalies = append(anomalies, types.AnomalyInfo{
				UnitName: u.Name, Score: score, Method: "baseline", ContributingMetrics: contributing,
			})
		}
	}
	sort.Slice(anomalies, func(i, j int) bool { return anomalies[i].Score > anomalies[j].Score })
	return anomalies
}
