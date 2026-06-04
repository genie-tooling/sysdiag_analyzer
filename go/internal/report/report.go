// Package report renders a SystemReport as JSON or a human text summary.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

// JSON returns the report as indented JSON (schema-compatible with the Python tool).
func JSON(r *types.SystemReport) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func pct(p *float64) string {
	if p == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", *p)
}

func deref(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// Text writes a concise human summary of the populated report sections.
func Text(r *types.SystemReport, w io.Writer) {
	fmt.Fprintf(w, "Host: %s   Boot: %s   %s\n", r.Hostname, r.BootID, r.Timestamp)
	if r.ResourceAnalysis != nil && r.ResourceAnalysis.SystemUsage != nil {
		su := r.ResourceAnalysis.SystemUsage
		fmt.Fprintf(w, "System: CPU %s   Mem %s   Swap %s\n", pct(su.CPUPercent), pct(su.MemPercent), pct(su.SwapPercent))
	}
	if b := r.BootAnalysis; b != nil && b.Times != nil && b.Times.Total != "" {
		fmt.Fprintf(w, "Boot: total %s (kernel %s, userspace %s)\n",
			b.Times.Total, b.Times.Kernel, b.Times.Userspace)
	}
	if l := r.LogAnalysis; l != nil && len(l.DetectedPatterns) > 0 {
		fmt.Fprintf(w, "Log patterns (%d entries analyzed):\n", l.TotalEntriesAnalyzed)
		for _, p := range l.DetectedPatterns {
			fmt.Fprintf(w, "  %-8s %-22s ×%d\n", p.PatternType, p.PatternKey, p.Count)
		}
	}
	if h := r.HealthAnalysis; h != nil {
		fmt.Fprintf(w, "Health: %d units · %d failed · %d flapping\n", h.AllUnitsCount, len(h.FailedUnits), len(h.FlappingUnits))
		for _, u := range h.FailedUnits {
			fmt.Fprintf(w, "  [FAILED]   %s (%s/%s)\n", u.Name, u.ActiveState, u.SubState)
		}
		for _, u := range h.FlappingUnits {
			fmt.Fprintf(w, "  [FLAPPING] %s (restarts=%s)\n", u.Name, u.Details["NRestarts"])
		}
	}
	if ra := r.ResourceAnalysis; ra != nil && len(ra.TopMemoryUnits) > 0 {
		fmt.Fprintf(w, "\nTop memory consumers:\n")
		fmt.Fprintf(w, "  %-40s %12s %12s %6s %12s\n", "UNIT", "MEM", "LIMIT", "%LIM", "ANON")
		for _, u := range ra.TopMemoryUnits {
			limit, pctStr := "none", "—"
			if u.MemoryMaxBytes != nil {
				limit = humanBytes(*u.MemoryMaxBytes)
				if p := u.MemoryPercentOfLimit(); p != nil {
					pctStr = fmt.Sprintf("%.0f%%", *p)
				}
			}
			anon := "—"
			if u.MemoryAnonBytes != nil {
				anon = humanBytes(*u.MemoryAnonBytes)
			}
			fmt.Fprintf(w, "  %-40s %12s %12s %6s %12s\n",
				trunc(u.Name, 40), humanBytes(deref(u.MemoryCurrentByte)), limit, pctStr, anon)
		}
	}
	if d := r.DependencyAnalysis; d != nil && len(d.FailedUnitDependencies) > 0 {
		fmt.Fprintf(w, "\nDependencies of failed units:\n")
		for _, fu := range d.FailedUnitDependencies {
			var prob []string
			for _, dep := range fu.Dependencies {
				if dep.IsProblematic {
					prob = append(prob, dep.Name)
				}
			}
			if len(prob) > 0 {
				fmt.Fprintf(w, "  %s → problematic: %s\n", fu.UnitName, strings.Join(prob, ", "))
			}
		}
	}
	if fd := r.FullDependencyAnalysis; fd != nil && len(fd.DetectedCycles) > 0 {
		fmt.Fprintf(w, "\nDependency cycles (%d):\n", len(fd.DetectedCycles))
		for _, c := range fd.DetectedCycles {
			fmt.Fprintf(w, "  %s → %s\n", strings.Join(c, " → "), c[0])
		}
	}
	if ml := r.MLAnalysis; ml != nil && len(ml.AnomaliesDetected) > 0 {
		fmt.Fprintf(w, "\nAnomalies (%d):\n", len(ml.AnomaliesDetected))
		for _, a := range ml.AnomaliesDetected {
			var parts []string
			for k, v := range a.ContributingMetrics {
				parts = append(parts, fmt.Sprintf("%s z=%.1f", k, v))
			}
			fmt.Fprintf(w, "  %-40s score=%.1f [%s] %s\n", trunc(a.UnitName, 40), a.Score, a.Method, strings.Join(parts, ", "))
		}
	}
	if lk := r.MemoryLeakAnalysis; lk != nil && len(lk.SuspectedLeaks) > 0 {
		fmt.Fprintf(w, "\nSuspected memory leaks (%d):\n", len(lk.SuspectedLeaks))
		for _, l := range lk.SuspectedLeaks {
			fmt.Fprintf(w, "  %-40s %s/h  (R²=%.2f, n=%d)\n",
				trunc(l.UnitName, 40), humanBytes(int64(l.SlopeBytesPerHour)), l.RSquared, l.Samples)
		}
	}
}
