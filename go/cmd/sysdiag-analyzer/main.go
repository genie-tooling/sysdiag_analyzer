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
	expHost          string
	expPort          int
	expInterval      int
	topSort          string
	topCount         int
	topInterval      int
)

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
			units, err := systemd.ListUnits(ctx)
			if err != nil {
				return fmt.Errorf("listing units: %w", err)
			}
			r := newReport()
			r.BootAnalysis = boot.Analyze()
			r.HealthAnalysis = health.Analyze(ctx, units) // populates unit Details (MainPID, NRestarts)
			r.ResourceAnalysis = resources.Analyze(ctx, units)
			r.LogAnalysis = logs.Analyze(0, logs.DefaultAnalysisLevel, since)

			states := make(map[string]types.UnitHealthInfo, len(units))
			for _, u := range units {
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
				active := activeServiceSet(units)
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
				r.LLMAnalysis = llm.Analyze(r, cfg.LLM)
			}
			if enableEBPF {
				r.EBPFAnalysis = ebpf.Run(ctx, 5*time.Second)
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
	runCmd.Flags().BoolVar(&analyzeML, "analyze-ml", false, "Statistical anomaly + leak detection (P2).")
	runCmd.Flags().StringVar(&since, "since", "", "Restrict log analysis to entries since this time (journalctl --since).")
	runCmd.Flags().BoolVar(&analyzeFullGraph, "analyze-full-graph", false, "Detect dependency cycles in the full graph.")
	runCmd.Flags().BoolVar(&analyzeLLM, "analyze-llm", false, "LLM synthesis of the report (Ollama / OpenAI-compatible).")

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
			r.LogAnalysis = logs.Analyze(0, logs.DefaultAnalysisLevel, since)
			return emit(r)
		},
	}
	logsCmd.Flags().StringVar(&since, "since", "", "Restrict to entries since this time (journalctl --since).")

	historyCmd := &cobra.Command{
		Use:   "show-history",
		Short: "List saved analysis reports.",
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg := config.Load(cfgPath)
			reports := history.Load(cfg.History.Directory, 0)
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
			coll := exporter.New(cfg)
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

	root.AddCommand(runCmd, healthCmd, resourcesCmd, bootCmd, logsCmd, historyCmd, topCmd, exporterCmd, configCmd)
	root.SetContext(context.Background())
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
