// Command sysdiag-analyzer is a Go port of the systemd diagnostics tool.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/collect/boot"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/collect/health"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/collect/logs"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/collect/resources"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/config"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/report"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/systemd"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

var (
	cfgPath    string
	outputFmt  string
	noSave     bool
	enableEBPF bool
	analyzeML  bool
	since      string
)

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
			units, err := systemd.ListUnits(ctx)
			if err != nil {
				return fmt.Errorf("listing units: %w", err)
			}
			r := newReport()
			r.BootAnalysis = boot.Analyze()
			r.HealthAnalysis = health.Analyze(ctx, units)
			r.ResourceAnalysis = resources.Analyze(ctx, units)
			r.LogAnalysis = logs.Analyze(0, logs.DefaultAnalysisLevel, since)
			// TODO: deps; history persistence (--no-save), --analyze-ml, --enable-ebpf, --analyze-llm.
			return emit(r)
		},
	}
	runCmd.Flags().BoolVar(&noSave, "no-save", false, "Do not save the report to history (P2).")
	runCmd.Flags().BoolVar(&enableEBPF, "enable-ebpf", false, "Enable eBPF tracing (P5).")
	runCmd.Flags().BoolVar(&analyzeML, "analyze-ml", false, "Statistical anomaly + leak detection (P2).")
	runCmd.Flags().StringVar(&since, "since", "", "Restrict log analysis to entries since this time (journalctl --since).")

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

	root.AddCommand(runCmd, healthCmd, resourcesCmd, bootCmd, logsCmd, configCmd)
	root.SetContext(context.Background())
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
