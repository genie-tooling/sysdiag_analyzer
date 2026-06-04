// Package exporter serves Prometheus metrics from a periodically-refreshed
// analysis, mirroring exporter.py (same metric names).
package exporter

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/analyze/stats"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/collect/deps"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/collect/health"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/collect/logs"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/collect/resources"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/config"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/features"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/history"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/systemd"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

const prefix = "sysdiag_analyzer_"

// Collector implements prometheus.Collector, serving from a cached report.
type Collector struct {
	cfg    config.Config
	mu     sync.RWMutex
	report *types.SystemReport
}

func New(cfg config.Config) *Collector { return &Collector{cfg: cfg} }

// Describe sends no descriptors -> registered as an unchecked collector
// (variable label sets across scrapes are fine).
func (c *Collector) Describe(chan<- *prometheus.Desc) {}

func metric(t prometheus.ValueType, name, help string, val float64, lvs ...string) prometheus.Metric {
	var labels, vals []string
	for i := 0; i+1 < len(lvs); i += 2 {
		labels = append(labels, lvs[i])
		vals = append(vals, lvs[i+1])
	}
	desc := prometheus.NewDesc(prefix+name, help, labels, nil)
	return prometheus.MustNewConstMetric(desc, t, val, vals...)
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	r := c.report
	c.mu.RUnlock()

	cycles := 0.0
	if r != nil && r.FullDependencyAnalysis != nil {
		cycles = float64(len(r.FullDependencyAnalysis.DetectedCycles))
	}
	ch <- metric(prometheus.GaugeValue, "dependency_cycles_detected", "Dependency cycles detected.", cycles)
	if r == nil {
		return
	}

	if r.MLAnalysis != nil {
		for _, a := range r.MLAnalysis.AnomaliesDetected {
			ch <- metric(prometheus.GaugeValue, "unit_anomaly_score", "Anomaly score (higher = more anomalous).", a.Score, "unit", a.UnitName)
		}
	}
	if h := r.HealthAnalysis; h != nil {
		emitProblem(ch, h.FailedUnits, "failed")
		emitProblem(ch, h.FlappingUnits, "flapping")
		emitProblem(ch, h.ProblematicSockets, "problematic_socket")
		emitProblem(ch, h.ProblematicTimers, "problematic_timer")
	}
	if ra := r.ResourceAnalysis; ra != nil {
		for _, g := range ra.ChildProcessGroups {
			if g.AggregatedMemoryBytes != nil {
				ch <- metric(prometheus.GaugeValue, "child_process_group_memory_bytes", "Child process group RSS.", float64(*g.AggregatedMemoryBytes), "parent_unit", g.ParentUnit, "command_name", g.CommandName)
			}
			if g.AggregatedCPUSecondsTot != nil {
				ch <- metric(prometheus.CounterValue, "child_process_group_cpu_seconds", "Child process group cumulative CPU.", *g.AggregatedCPUSecondsTot, "parent_unit", g.ParentUnit, "command_name", g.CommandName)
			}
		}
		top := map[string]bool{}
		for _, u := range ra.TopMemoryUnits {
			top[u.Name] = true
		}
		emitted := map[string]bool{}
		for _, u := range ra.UnitUsage {
			if u.MemoryCurrentByte == nil || emitted[u.Name] {
				continue
			}
			if u.MemoryMaxBytes == nil && u.MemoryHighBytes == nil && !top[u.Name] {
				continue // bound cardinality: limited units or top consumers only
			}
			emitted[u.Name] = true
			ch <- metric(prometheus.GaugeValue, "unit_memory_current_bytes", "Unit cgroup memory.current.", float64(*u.MemoryCurrentByte), "unit", u.Name)
			if u.MemoryMaxBytes != nil {
				ch <- metric(prometheus.GaugeValue, "unit_memory_max_bytes", "Unit memory.max (absent = no hard limit).", float64(*u.MemoryMaxBytes), "unit", u.Name)
			}
			if u.MemoryHighBytes != nil {
				ch <- metric(prometheus.GaugeValue, "unit_memory_high_bytes", "Unit memory.high.", float64(*u.MemoryHighBytes), "unit", u.Name)
			}
			if u.MemoryAnonBytes != nil {
				ch <- metric(prometheus.GaugeValue, "unit_memory_anon_bytes", "Unit anon memory (leak signal; deriv() in PromQL).", float64(*u.MemoryAnonBytes), "unit", u.Name)
			}
		}
	}
	if r.LogAnalysis != nil {
		for _, p := range r.LogAnalysis.DetectedPatterns {
			level := p.Level
			if level == "" {
				level = "unknown"
			}
			ch <- metric(prometheus.CounterValue, "log_patterns_detected", "Detected log pattern occurrences.", float64(p.Count), "pattern_key", p.PatternKey, "level", level)
		}
	}
}

func emitProblem(ch chan<- prometheus.Metric, units []types.UnitHealthInfo, kind string) {
	for _, u := range units {
		ch <- metric(prometheus.GaugeValue, "unit_problem_status", "1 if a unit has a specific problem.", 1.0, "unit", u.Name, "problem_type", kind)
	}
}

// RunPeriodic refreshes the cached report immediately and then on each interval.
func (c *Collector) RunPeriodic(ctx context.Context, interval time.Duration) {
	c.collectOnce(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.collectOnce(ctx)
		}
	}
}

func (c *Collector) collectOnce(ctx context.Context) {
	units, err := systemd.ListUnits(ctx)
	if err != nil {
		return
	}
	r := &types.SystemReport{Timestamp: time.Now().UTC().Format(time.RFC3339)}
	r.HealthAnalysis = health.Analyze(ctx, units) // populates Details (MainPID) used below
	r.ResourceAnalysis = resources.Analyze(ctx, units)
	r.LogAnalysis = logs.Analyze(0, logs.DefaultAnalysisLevel, "")
	names := make([]string, len(units))
	for i, u := range units {
		names[i] = u.Name
	}
	r.FullDependencyAnalysis = deps.AnalyzeFullGraph(names)

	reports := append(history.Load(c.cfg.History.Directory, c.cfg.Models.HistoryWindow), r)
	feats := features.Extract(reports)
	active := map[string]bool{}
	for _, u := range units {
		if strings.HasSuffix(u.Name, ".service") {
			if pid, err := strconv.Atoi(u.Details["MainPID"]); err == nil && pid > 0 {
				active[u.Name] = true
			}
		}
	}
	r.MLAnalysis = &types.MLAnalysisResult{
		AnomaliesDetected:        stats.DetectAnomalies(feats, c.cfg.Models.Sensitivity, active),
		UnitsAnalyzedCount:       len(active),
		SkippedZeroVarianceUnits: []string{},
	}

	c.mu.Lock()
	c.report = r
	c.mu.Unlock()
}
