// Command sysdiag-analyzer is a Go port of the systemd diagnostics tool.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/analyze/baseline"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/analyze/leak"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/analyze/llm"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/analyze/stats"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/collect/boot"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/collect/deps"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/collect/health"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/collect/logs"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/collect/resources"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/config"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/ebpf"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/exporter"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/features"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/history"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/report"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/systemd"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/tui"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

var (
	cfgPath          string
	outputFmt        string
	noSave           bool
	enableEBPF       bool
	analyzeML        bool
	analyzeLLM       bool
	analyzeFullGraph bool
	since            string
	showTiming       bool
	ebpfDur          time.Duration
	llmModel         string
	logBoot          int
	logPriority      int
	histLimit        int
	expHost          string
	expPort          int
	expInterval      int
	expEnableEBPF    bool
	topSort          string
	topCount         int
	topInterval      int
)

// runSingleUnit performs a focused analysis of one unit (analyze-unit),
// mirroring unit_analyzer.py.
func runSingleUnit(_ context.Context, unitName string) *types.SingleUnitReport {
	rep := &types.SingleUnitReport{}
	propsNeeded := append([]string{"LoadState", "ActiveState", "SubState", "Description",
		"NRestarts", "Result", "MainPID", "Refused"}, deps.RelationProps()...)
	props := systemd.ShowProperties([]string{unitName}, propsNeeded)
	var canonical string
	var kv map[string]string
	for id, m := range props {
		canonical, kv = id, m
		break
	}
	if kv == nil {
		rep.AnalysisError = fmt.Sprintf("Unit '%s' not found or properties could not be fetched.", unitName)
		return rep
	}
	u := types.UnitHealthInfo{
		Name: canonical, LoadState: kv["LoadState"], ActiveState: kv["ActiveState"],
		SubState: kv["SubState"], Description: kv["Description"], Details: kv,
	}
	u.IsFailed = u.ActiveState == "failed"
	u.RecentLogs = systemd.UnitLogs(canonical, 50)
	rep.UnitInfo = &u
	if usages := resources.CollectUnitUsage([]types.UnitHealthInfo{u}, map[string]string{}); len(usages) > 0 {
		rep.ResourceUsage = &usages[0]
		if rep.ResourceUsage.CgroupPath != "" {
			rep.Processes = resources.UnitProcesses(rep.ResourceUsage.CgroupPath)
		}
	}
	rep.DependencyInfo = deps.AnalyzeUnit(canonical, kv, nil)
	return rep
}

func emitSingle(rep *types.SingleUnitReport) error {
	if outputFmt == "json" {
		b, err := report.JSONSingle(rep)
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	report.SingleUnit(rep, os.Stdout)
	return nil
}

// activeServiceSet returns .service units that have a live MainPID (the ML target set).
func activeServiceSet(units []types.UnitHealthInfo) map[string]bool {
	out := map[string]bool{}
	for _, u := range units {
		if !strings.HasSuffix(u.Name, ".service") {
			continue
		}
		if pid, err := strconv.Atoi(u.Details["MainPID"]); err == nil && pid > 0 {
			out[u.Name] = true
		}
	}
	return out
}

func newReport() *types.SystemReport {
	return &types.SystemReport{
		Hostname:  systemd.Hostname(),
		BootID:    systemd.BootID(),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Errors:    []string{},
	}
}

func emit(r *types.SystemReport) error {
	if outputFmt == "json" {
		b, err := report.JSON(r)
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	report.Text(r, os.Stdout)
	return nil
}

func main() {
	root := &cobra.Command{
		Use:           "sysdiag-analyzer",
		Short:         "Systemd & system health diagnostics (Go port)",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVarP(&cfgPath, "config", "c", "", "Path to a TOML config file.")
	root.PersistentFlags().StringVarP(&outputFmt, "output", "o", "rich", "Output format: rich | json.")

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run the full analysis.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cfg := config.Load(cfgPath)

			// Start eBPF first so its window overlaps the rest of the analysis
			// (the tracer accumulates in-kernel while we collect everything else).
			var ebpfSess *ebpf.Session
			var ebpfErr string
			ebpfStarted := time.Now()
			if enableEBPF {
				if s, err := ebpf.Start(ctx); err == nil {
					ebpfSess = s
					defer s.Close()
				} else {
					ebpfErr = err.Error()
				}
			}

			tList := time.Now()
			units, err := systemd.ListUnits(ctx)
			if err != nil {
				return fmt.Errorf("listing units: %w", err)
			}
			listDur := time.Since(tList)
			r := newReport()
			// These four are independent and run concurrently. health mutates its
			// units (Details/flags), so give it a private copy — resources reads the
			// original list, avoiding a data race on the shared slice.
			healthUnits := append([]types.UnitHealthInfo(nil), units...)
			var ph struct{ boot, health, resources, logs time.Duration }
			var wg sync.WaitGroup
			wg.Add(4)
			go func() { defer wg.Done(); t := time.Now(); r.BootAnalysis = boot.Analyze(); ph.boot = time.Since(t) }()
			go func() {
				defer wg.Done()
				t := time.Now()
				r.HealthAnalysis = health.Analyze(ctx, healthUnits)
				ph.health = time.Since(t)
			}()
			go func() {
				defer wg.Done()
				t := time.Now()
				r.ResourceAnalysis = resources.Analyze(ctx, units)
				ph.resources = time.Since(t)
			}()
			go func() {
				defer wg.Done()
				t := time.Now()
				r.LogAnalysis = logs.Analyze(0, logs.DefaultAnalysisLevel, since)
				ph.logs = time.Since(t)
			}()
			wg.Wait()
			if showTiming {
				ms := func(d time.Duration) string { return d.Round(time.Millisecond).String() }
				fmt.Fprintf(os.Stderr, "timing: list-units=%s | parallel: boot=%s health=%s resources=%s logs=%s\n",
					ms(listDur), ms(ph.boot), ms(ph.health), ms(ph.resources), ms(ph.logs))
			}

			// healthUnits carries the fetched Details (MainPID, NRestarts, ...).
			states := make(map[string]types.UnitHealthInfo, len(healthUnits))
			for _, u := range healthUnits {
				states[u.Name] = u
			}
			if len(r.HealthAnalysis.FailedUnits) > 0 {
				r.DependencyAnalysis = deps.AnalyzeFailed(r.HealthAnalysis.FailedUnits, states)
			}
			if analyzeFullGraph {
				names := make([]string, len(units))
				for i, u := range units {
					names[i] = u.Name
				}
				r.FullDependencyAnalysis = deps.AnalyzeFullGraph(names)
			}
			if analyzeML {
				reports := append(history.Load(cfg.History.Directory, cfg.Models.HistoryWindow), r)
				feats := features.Extract(reports)
				active := activeServiceSet(healthUnits)
				var usage []types.UnitResourceUsage
				if r.ResourceAnalysis != nil {
					usage = r.ResourceAnalysis.UnitUsage
				}
				switch cfg.Models.Method {
				case "baseline":
					// Online, adaptive EWMA/seasonal baseline (stateful across runs).
					stPath := filepath.Join(cfg.Models.Directory, "baseline.json")
					st := baseline.Load(stPath)
					now := float64(time.Now().Unix())
					anomalies := baseline.Detect(st, usage, now, cfg.Models.Sensitivity,
						cfg.Models.Seasonal, cfg.Models.EWMAAlpha, cfg.Models.MinUpdates, nil)
					st.Prune(now, 7*24*3600)
					if err := st.Save(stPath); err != nil {
						r.Errors = append(r.Errors, "saving baseline state: "+err.Error())
					}
					r.MLAnalysis = &types.MLAnalysisResult{
						AnomaliesDetected:        anomalies,
						UnitsAnalyzedCount:       len(usage),
						SkippedZeroVarianceUnits: []string{},
					}
				default: // "statistical" (window-based, stateless)
					if cfg.Models.Method == "lstm" {
						r.Errors = append(r.Errors,
							"models.method=lstm is not available in this build (build with -tags lstm); falling back to statistical")
					}
					r.MLAnalysis = &types.MLAnalysisResult{
						AnomaliesDetected:        stats.DetectAnomalies(feats, cfg.Models.Sensitivity, active),
						UnitsAnalyzedCount:       len(active),
						SkippedZeroVarianceUnits: []string{},
					}
				}
				lk, n := leak.Detect(feats, nil)
				r.MemoryLeakAnalysis = &types.MemoryLeakAnalysisResult{SuspectedLeaks: lk, UnitsAnalyzedCount: n}
			}
			if analyzeLLM {
				if llmModel != "" {
					cfg.LLM.Model = llmModel
				}
				r.LLMAnalysis = llm.Analyze(r, cfg.LLM)
			}
			if enableEBPF {
				if ebpfSess != nil {
					// Wait only for whatever window remains after the overlap.
					if rem := ebpfDur - time.Since(ebpfStarted); rem > 0 {
						select {
						case <-ctx.Done():
						case <-time.After(rem):
						}
					}
					r.EBPFAnalysis = ebpfSess.Snapshot()
				} else {
					r.EBPFAnalysis = &types.EBPFAnalysisResult{
						UnitsWithExecs: map[string]int{}, UnitsWithExits: map[string]int{}, Error: ebpfErr,
					}
				}
			}
			if !noSave {
				if err := history.Save(r, cfg.History.Directory, cfg.History.MaxFiles); err != nil {
					r.Errors = append(r.Errors, "failed to save report: "+err.Error())
				}
			}
			return emit(r)
		},
	}
	runCmd.Flags().BoolVar(&noSave, "no-save", false, "Do not save the report to history (P2).")
	runCmd.Flags().BoolVar(&enableEBPF, "enable-ebpf", false, "Enable eBPF tracing (P5).")
	runCmd.Flags().DurationVar(&ebpfDur, "ebpf-duration", 3*time.Second, "eBPF aggregation window (overlaps the rest of the analysis).")
	runCmd.Flags().BoolVar(&showTiming, "timing", false, "Print per-phase wall-clock timing to stderr.")
	runCmd.Flags().BoolVar(&analyzeML, "analyze-ml", false, "Statistical anomaly + leak detection (P2).")
	runCmd.Flags().StringVar(&since, "since", "", "Restrict log analysis to entries since this time (journalctl --since).")
	runCmd.Flags().BoolVar(&analyzeFullGraph, "analyze-full-graph", false, "Detect dependency cycles in the full graph.")
	runCmd.Flags().BoolVar(&analyzeLLM, "analyze-llm", false, "LLM synthesis of the report (Ollama / OpenAI-compatible / claude-code).")
	runCmd.Flags().StringVar(&llmModel, "llm-model", "", "Override [llm].model for this run.")

	healthCmd := &cobra.Command{
		Use:   "analyze-health",
		Short: "Service health analysis only.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			units, err := systemd.ListUnits(cmd.Context())
			if err != nil {
				return err
			}
			r := newReport()
			r.HealthAnalysis = health.Analyze(cmd.Context(), units)
			return emit(r)
		},
	}

	resourcesCmd := &cobra.Command{
		Use:   "analyze-resources",
		Short: "Resource utilization analysis only.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			units, err := systemd.ListUnits(cmd.Context())
			if err != nil {
				return err
			}
			r := newReport()
			r.ResourceAnalysis = resources.Analyze(cmd.Context(), units)
			return emit(r)
		},
	}

	bootCmd := &cobra.Command{
		Use:   "analyze-boot",
		Short: "Boot performance analysis only.",
		RunE: func(_ *cobra.Command, _ []string) error {
			r := newReport()
			r.BootAnalysis = boot.Analyze()
			return emit(r)
		},
	}

	logsCmd := &cobra.Command{
		Use:   "analyze-logs",
		Short: "Log analysis only.",
		RunE: func(_ *cobra.Command, _ []string) error {
			r := newReport()
			r.LogAnalysis = logs.Analyze(logBoot, logPriority, since)
			return emit(r)
		},
	}
	logsCmd.Flags().StringVar(&since, "since", "", "Restrict to entries since this time (journalctl --since).")
	logsCmd.Flags().IntVarP(&logBoot, "boot", "b", 0, "Boot offset (0=current, -1=previous, ...).")
	logsCmd.Flags().IntVarP(&logPriority, "priority", "p", logs.DefaultAnalysisLevel, "Min syslog priority (0=emerg .. 7=debug).")

	unitCmd := &cobra.Command{
		Use:   "analyze-unit <unit>",
		Short: "Focused analysis of a single systemd unit.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return emitSingle(runSingleUnit(cmd.Context(), args[0]))
		},
	}

	historyCmd := &cobra.Command{
		Use:   "show-history",
		Short: "List saved analysis reports.",
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg := config.Load(cfgPath)
			reports := history.Load(cfg.History.Directory, histLimit)
			if len(reports) == 0 {
				fmt.Printf("No history found in %s\n", cfg.History.Directory)
				return nil
			}
			for _, rep := range reports {
				failed, anom, leaks := 0, 0, 0
				if rep.HealthAnalysis != nil {
					failed = len(rep.HealthAnalysis.FailedUnits)
				}
				if rep.MLAnalysis != nil {
					anom = len(rep.MLAnalysis.AnomaliesDetected)
				}
				if rep.MemoryLeakAnalysis != nil {
					leaks = len(rep.MemoryLeakAnalysis.SuspectedLeaks)
				}
				fmt.Printf("%s  %-20s  failed=%d anomalies=%d leaks=%d\n",
					rep.Timestamp, rep.Hostname, failed, anom, leaks)
			}
			return nil
		},
	}
	historyCmd.Flags().IntVarP(&histLimit, "limit", "n", 5, "Number of recent reports to show.")

	topCmd := &cobra.Command{
		Use:   "top",
		Short: "Live, top-like view of per-unit cgroup usage (Ctrl-C/q to quit).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return tui.Run(cmd.Context(), config.Load(cfgPath),
				time.Duration(topInterval)*time.Second, topSort, topCount)
		},
	}
	topCmd.Flags().IntVarP(&topInterval, "interval", "i", 2, "Refresh interval (seconds).")
	topCmd.Flags().StringVarP(&topSort, "sort", "s", "mem", "Sort by: mem | cpu | io | limit.")
	topCmd.Flags().IntVarP(&topCount, "count", "n", 25, "Number of units to display.")

	exporterCmd := &cobra.Command{
		Use:   "exporter",
		Short: "Run a persistent Prometheus exporter.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := config.Load(cfgPath)
			coll := exporter.New(cfg, expEnableEBPF)
			prometheus.MustRegister(coll)
			go coll.RunPeriodic(cmd.Context(), time.Duration(expInterval)*time.Second)
			http.Handle("/metrics", promhttp.Handler())
			addr := fmt.Sprintf("%s:%d", expHost, expPort)
			fmt.Printf("Prometheus exporter listening on http://%s/metrics (Ctrl-C to quit)\n", addr)
			return http.ListenAndServe(addr, nil)
		},
	}
	exporterCmd.Flags().StringVar(&expHost, "host", "0.0.0.0", "Bind address.")
	exporterCmd.Flags().IntVar(&expPort, "port", 9822, "Port.")
	exporterCmd.Flags().IntVarP(&expInterval, "interval", "i", 60, "Background refresh interval (seconds).")
	exporterCmd.Flags().BoolVar(&expEnableEBPF, "enable-ebpf", false, "Continuously trace per-unit eBPF counters (needs root + -tags ebpf build; adds probe overhead).")

	configCmd := &cobra.Command{Use: "config", Short: "Configuration commands."}
	configShow := &cobra.Command{
		Use:   "show",
		Short: "Show the effective merged configuration.",
		RunE: func(_ *cobra.Command, _ []string) error {
			b, _ := json.MarshalIndent(config.Load(cfgPath), "", "  ")
			fmt.Println(string(b))
			return nil
		},
	}
	configCmd.AddCommand(configShow)

	root.AddCommand(runCmd, healthCmd, resourcesCmd, bootCmd, logsCmd, unitCmd, historyCmd, topCmd, exporterCmd, configCmd)
	root.SetContext(context.Background())
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
