// Package tui implements the live `top` view (bubbletea). state.go holds the
// pure rolling-history logic (CPU%/IO rates, anon trend, leak flag) — a port of
// tui.py's TopState, testable without a terminal.
package tui

import (
	"sort"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

const (
	defaultWindow     = 8
	leakMinGrowth     = 16 * 1024 * 1024 // bytes
	leakMinGrowthFrac = 0.05
	leakMaxDips       = 1
)

type sample struct {
	ts                      float64
	cpuNsec, anon, ioR, ioW *int64
}

// Derived holds per-unit values computed from history for a refresh.
type Derived struct {
	CPUPct      *float64
	IOReadRate  *float64 // bytes/sec
	IOWriteRate *float64
	MemTrend    string // "▲" / "▼" / ""
	Leaking     bool
}

// State is the rolling per-unit history.
type State struct {
	window  int
	hist    map[string][]sample
	netPrev *[3]float64 // ts, sent, recv
}

func NewState() *State { return &State{window: defaultWindow, hist: map[string][]sample{}} }

// Update ingests a new snapshot and returns per-unit derived metrics.
func (s *State) Update(usages []types.UnitResourceUsage, now float64) map[string]Derived {
	live := map[string]bool{}
	derived := map[string]Derived{}
	for i := range usages {
		u := &usages[i]
		live[u.Name] = true
		h := s.hist[u.Name]
		var d Derived
		if len(h) > 0 {
			prev := h[len(h)-1]
			if dt := now - prev.ts; dt > 0 {
				d.CPUPct = ratePct(prev.cpuNsec, u.CPUUsageNsec, dt)
				d.IOReadRate = rate(prev.ioR, u.IOReadBytes, dt)
				d.IOWriteRate = rate(prev.ioW, u.IOWriteBytes, dt)
				d.MemTrend = trend(prev.anon, u.MemoryAnonBytes)
			}
		}
		h = append(h, sample{ts: now, cpuNsec: u.CPUUsageNsec, anon: u.MemoryAnonBytes, ioR: u.IOReadBytes, ioW: u.IOWriteBytes})
		if len(h) > s.window {
			h = h[len(h)-s.window:]
		}
		s.hist[u.Name] = h
		d.Leaking = s.isLeaking(h)
		derived[u.Name] = d
	}
	for name := range s.hist {
		if !live[name] {
			delete(s.hist, name)
		}
	}
	return derived
}

func (s *State) isLeaking(h []sample) bool {
	anon := make([]float64, 0, len(h))
	for _, x := range h {
		if x.anon != nil {
			anon = append(anon, float64(*x.anon))
		}
	}
	if len(anon) < s.window {
		return false
	}
	dips := 0
	for i := 1; i < len(anon); i++ {
		if anon[i] < anon[i-1] {
			dips++
		}
	}
	if dips > leakMaxDips {
		return false
	}
	growth := anon[len(anon)-1] - anon[0]
	return growth >= leakMinGrowth && growth >= anon[0]*leakMinGrowthFrac
}

// NetRate returns system-wide (sentBps, recvBps) from successive counters.
func (s *State) NetRate(su *types.SystemResourceUsage, now float64) (*float64, *float64) {
	if su == nil || su.NetIOSentBytes == nil || su.NetIORecvBytes == nil {
		return nil, nil
	}
	cur := [3]float64{now, float64(*su.NetIOSentBytes), float64(*su.NetIORecvBytes)}
	prev := s.netPrev
	s.netPrev = &cur
	if prev == nil || now-prev[0] <= 0 {
		return nil, nil
	}
	dt := now - prev[0]
	up := (cur[1] - prev[1]) / dt
	down := (cur[2] - prev[2]) / dt
	return &up, &down
}

func ratePct(prev, cur *int64, dt float64) *float64 {
	if prev == nil || cur == nil || *cur < *prev {
		return nil
	}
	v := float64(*cur-*prev) / (dt * 1e9) * 100.0
	return &v
}

func rate(prev, cur *int64, dt float64) *float64 {
	if prev == nil || cur == nil || *cur < *prev {
		return nil
	}
	v := float64(*cur-*prev) / dt
	return &v
}

func trend(prev, cur *int64) string {
	if prev == nil || cur == nil {
		return ""
	}
	switch {
	case *cur > *prev:
		return "▲"
	case *cur < *prev:
		return "▼"
	default:
		return ""
	}
}

// SortUsages orders units by the given key (mem|cpu|io|limit).
func SortUsages(units []types.UnitResourceUsage, key string) {
	switch key {
	case "cpu":
		sort.SliceStable(units, func(i, j int) bool { return d64(units[i].CPUUsageNsec) > d64(units[j].CPUUsageNsec) })
	case "io":
		sort.SliceStable(units, func(i, j int) bool {
			return d64(units[i].IOReadBytes)+d64(units[i].IOWriteBytes) > d64(units[j].IOReadBytes)+d64(units[j].IOWriteBytes)
		})
	case "limit":
		sort.SliceStable(units, func(i, j int) bool { return pctOrNeg(units[i]) > pctOrNeg(units[j]) })
	default:
		sort.SliceStable(units, func(i, j int) bool { return d64(units[i].MemoryCurrentByte) > d64(units[j].MemoryCurrentByte) })
	}
}

func d64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func pctOrNeg(u types.UnitResourceUsage) float64 {
	if p := u.MemoryPercentOfLimit(); p != nil {
		return *p
	}
	return -1
}
