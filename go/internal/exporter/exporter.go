// Package exporter serves Prometheus metrics from a periodically-refreshed
// analysis, mirroring exporter.py (same metric names).
package exporter

import (
	"context"
	"fmt"
	"os"
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
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/ebpf"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/features"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/history"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/systemd"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

const prefix = "sysdiag_analyzer_"

// Collector implements prometheus.Collector, serving from a cached report.
// With eBPF enabled it also holds a live tracer session read on each scrape.
type Collector struct {
	cfg        config.Config
	enableEBPF bool
	mu         sync.RWMutex
	report     *types.SystemReport
	sess       *ebpf.Session
}

func New(cfg config.Config, enableEBPF bool) *Collector {
	return &Collector{cfg: cfg, enableEBPF: enableEBPF}
}

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
			if u.MemoryPgMajfault != nil {
				ch <- metric(prometheus.CounterValue, "unit_pgmajfault_total", "Unit cumulative major page faults (thrash signal; rate() in PromQL).", float64(*u.MemoryPgMajfault), "unit", u.Name)
			}
			if u.PSIMemPressure != nil {
				ch <- metric(prometheus.GaugeValue, "unit_memory_pressure_ratio", "Unit memory PSI: % of the last 10s with a task stalled on memory.", *u.PSIMemPressure, "unit", u.Name)
			}
			if u.PSIIOPressure != nil {
				ch <- metric(prometheus.GaugeValue, "unit_io_pressure_ratio", "Unit io PSI: % of the last 10s with a task stalled on I/O.", *u.PSIIOPressure, "unit", u.Name)
			}
			if u.PSICPUPressure != nil {
				ch <- metric(prometheus.GaugeValue, "unit_cpu_pressure_ratio", "Unit cpu PSI: % of the last 10s with a task stalled on CPU.", *u.PSICPUPressure, "unit", u.Name)
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

	// eBPF: live, cumulative-since-start counters (use rate() in PromQL).
	c.mu.RLock()
	sess := c.sess
	c.mu.RUnlock()
	if sess != nil {
		for _, s := range sess.Snapshot().UnitStats {
			ch <- metric(prometheus.CounterValue, "unit_proc_execs_total", "Process execs in a unit.", float64(s.Execs), "unit", s.Unit)
			ch <- metric(prometheus.CounterValue, "unit_proc_exits_total", "Process exits in a unit.", float64(s.Exits), "unit", s.Unit)
			ch <- metric(prometheus.CounterValue, "unit_proc_abnormal_exits_total", "Process exits by signal or nonzero code.", float64(s.ExitNonzero+s.ExitSignaled), "unit", s.Unit)
			ch <- metric(prometheus.CounterValue, "unit_oom_kills_total", "OOM kills attributed to a unit.", float64(s.OOMKills), "unit", s.Unit)
			ch <- metric(prometheus.CounterValue, "unit_sigkill_received_total", "SIGKILLs delivered to a unit's processes.", float64(s.SigKillRcvd), "unit", s.Unit)
			ch <- metric(prometheus.CounterValue, "unit_offcpu_seconds_total", "Time a unit spent off-CPU in D-state.", float64(s.OffCPUNs)/1e9, "unit", s.Unit)
			if s.IOOps > 0 {
				ch <- metric(prometheus.CounterValue, "unit_io_latency_seconds_total", "Summed block-I/O latency (rate(sum)/rate(ops)=avg).", float64(s.IOLatencyUsSum)/1e6, "unit", s.Unit)
				ch <- metric(prometheus.CounterValue, "unit_io_ops_total", "Completed block I/O ops attributed to a unit.", float64(s.IOOps), "unit", s.Unit)
			}
		}
	}
}

func emitProblem(ch chan<- prometheus.Metric, units []types.UnitHealthInfo, kind string) {
	for _, u := range units {
		ch <- metric(prometheus.GaugeValue, "unit_problem_status", "1 if a unit has a specific problem.", 1.0, "unit", u.Name, "problem_type", kind)
	}
}

// RunPeriodic refreshes the cached report immediately and then on each interval.
// If eBPF is enabled, it starts a persistent tracer session for its lifetime.
func (c *Collector) RunPeriodic(ctx context.Context, interval time.Duration) {
	if c.enableEBPF {
		if s, err := ebpf.Start(ctx); err == nil {
			c.mu.Lock()
			c.sess = s
			c.mu.Unlock()
			defer func() {
				c.mu.Lock()
				s.Close()
				c.sess = nil
				c.mu.Unlock()
			}()
		} else {
			fmt.Fprintln(os.Stderr, "exporter: eBPF metrics disabled: "+err.Error())
		}
	}
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
