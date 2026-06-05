// Package report renders a SystemReport as JSON or a styled human summary.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/ui"
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

func pctStr(p *float64) string {
	if p == nil {
		return ui.DimS.Render("n/a")
	}
	return ui.PctStyle(*p).Render(fmt.Sprintf("%.1f%%", *p))
}

// zStr formats a z-score, collapsing the constant-baseline sentinel to "∞".
func zStr(v float64) string {
	if v >= 1e6 {
		return "∞"
	}
	return fmt.Sprintf("%.1f", v)
}

func deref(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func trunc(s string, n int) string {
	if lipgloss.Width(s) <= n {
		return s
	}
	r := []rune(s)
	if n <= 1 {
		return "…"
	}
	return string(r[:n-1]) + "…"
}

// newTable builds a rounded, accent-headed table; columns in rightCols are
// right-aligned (numeric), the rest left-aligned.
func newTable(headers []string, rightCols ...int) *table.Table {
	right := map[int]bool{}
	for _, c := range rightCols {
		right[c] = true
	}
	return table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(ui.BorderS).
		Headers(headers...).
		StyleFunc(func(row, col int) lipgloss.Style {
			st := lipgloss.NewStyle().Padding(0, 1)
			if right[col] {
				st = st.Align(lipgloss.Right)
			}
			if row == table.HeaderRow {
				st = st.Bold(true).Foreground(ui.Accent)
			}
			return st
		})
}

// Text writes a styled, colorful summary of the populated report sections.
func Text(r *types.SystemReport, w io.Writer) {
	// Banner.
	title := lipgloss.NewStyle().Bold(true).Foreground(ui.Accent).Render("sysdiag-analyzer")
	meta := ui.DimS.Render(fmt.Sprintf("%s  ·  boot %s  ·  %s",
		r.Hostname, trunc(r.BootID, 12), r.Timestamp))
	banner := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).BorderForeground(ui.Accent).Padding(0, 1).
		Render(title + "   " + meta)
	fmt.Fprintln(w, banner)

	if r.ResourceAnalysis != nil && r.ResourceAnalysis.SystemUsage != nil {
		su := r.ResourceAnalysis.SystemUsage
		fmt.Fprintf(w, "%s  CPU %s   Mem %s   Swap %s\n",
			ui.CyanS.Render("system"), pctStr(su.CPUPercent), pctStr(su.MemPercent), pctStr(su.SwapPercent))
	}
	if b := r.BootAnalysis; b != nil && b.Times != nil && b.Times.Total != "" {
		fmt.Fprintf(w, "%s    total %s   %s\n",
			ui.CyanS.Render("boot  "), lipgloss.NewStyle().Bold(true).Render(b.Times.Total),
			ui.DimS.Render(fmt.Sprintf("kernel %s · userspace %s", b.Times.Kernel, b.Times.Userspace)))
	}

	renderHealth(r, w)
	renderTopMemory(r, w)
	renderLogs(r, w)
	renderAnomalies(r, w)
	renderLeaks(r, w)
	renderDeps(r, w)
	renderLLM(r, w)
}

func renderHealth(r *types.SystemReport, w io.Writer) {
	h := r.HealthAnalysis
	if h == nil {
		return
	}
	fmt.Fprintln(w, ui.Section("Health"))
	fmt.Fprintf(w, "  %s %d failed    %s %d flapping    %s %d units total\n",
		ui.Dot(ui.BadS), len(h.FailedUnits), ui.Dot(ui.WarnS), len(h.FlappingUnits),
		ui.Dot(ui.GoodS), h.AllUnitsCount)
	if len(h.FailedUnits) == 0 && len(h.FlappingUnits) == 0 {
		return
	}
	t := newTable([]string{"", "UNIT", "STATE", "DETAIL"})
	for _, u := range h.FailedUnits {
		t.Row(ui.BadS.Render("✗"), trunc(u.Name, 44),
			ui.BadS.Render(fmt.Sprintf("%s/%s", u.ActiveState, u.SubState)), u.Description)
	}
	for _, u := range h.FlappingUnits {
		t.Row(ui.WarnS.Render("≈"), trunc(u.Name, 44),
			ui.WarnS.Render("flapping"), "restarts="+u.Details["NRestarts"])
	}
	fmt.Fprintln(w, t)
}

func renderTopMemory(r *types.SystemReport, w io.Writer) {
	ra := r.ResourceAnalysis
	if ra == nil || len(ra.TopMemoryUnits) == 0 {
		return
	}
	fmt.Fprintln(w, ui.Section("Top memory consumers"))
	t := newTable([]string{"UNIT", "MEM", "LIMIT", "%LIM", "ANON"}, 1, 2, 3, 4)
	for _, u := range ra.TopMemoryUnits {
		limit, lpct := ui.DimS.Render("none"), ui.DimS.Render("—")
		if u.MemoryMaxBytes != nil {
			limit = humanBytes(*u.MemoryMaxBytes)
			if p := u.MemoryPercentOfLimit(); p != nil {
				lpct = ui.PctStyle(*p).Render(fmt.Sprintf("%.0f%%", *p))
			}
		}
		anon := ui.DimS.Render("—")
		if u.MemoryAnonBytes != nil {
			anon = humanBytes(*u.MemoryAnonBytes)
		}
		t.Row(trunc(u.Name, 44), humanBytes(deref(u.MemoryCurrentByte)), limit, lpct, anon)
	}
	fmt.Fprintln(w, t)
}

func renderLogs(r *types.SystemReport, w io.Writer) {
	l := r.LogAnalysis
	if l == nil || len(l.DetectedPatterns) == 0 {
		return
	}
	fmt.Fprintln(w, ui.Section(fmt.Sprintf("Log patterns  (%d entries analyzed)", l.TotalEntriesAnalyzed)))
	t := newTable([]string{"TYPE", "KEY", "COUNT"}, 2)
	for _, p := range l.DetectedPatterns {
		typeStyle := ui.WarnS
		if strings.Contains(strings.ToLower(p.PatternType), "oom") ||
			strings.Contains(strings.ToLower(p.PatternType), "error") {
			typeStyle = ui.BadS
		}
		t.Row(typeStyle.Render(p.PatternType), trunc(p.PatternKey, 50), fmt.Sprintf("%d", p.Count))
	}
	fmt.Fprintln(w, t)
}

func renderAnomalies(r *types.SystemReport, w io.Writer) {
	ml := r.MLAnalysis
	if ml == nil || len(ml.AnomaliesDetected) == 0 {
		return
	}
	fmt.Fprintln(w, ui.Section(fmt.Sprintf("Anomalies  (%d)", len(ml.AnomaliesDetected))))
	t := newTable([]string{"UNIT", "SCORE", "METHOD", "CONTRIBUTING"}, 1)
	for _, a := range ml.AnomaliesDetected {
		keys := make([]string, 0, len(a.ContributingMetrics))
		for k := range a.ContributingMetrics {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, k+" "+zStr(a.ContributingMetrics[k]))
		}
		t.Row(trunc(a.UnitName, 40), ui.WarnS.Render(zStr(a.Score)),
			ui.DimS.Render(a.Method), trunc(strings.Join(parts, ", "), 56))
	}
	fmt.Fprintln(w, t)
}

func renderLeaks(r *types.SystemReport, w io.Writer) {
	lk := r.MemoryLeakAnalysis
	if lk == nil || len(lk.SuspectedLeaks) == 0 {
		return
	}
	fmt.Fprintln(w, ui.Section(fmt.Sprintf("Suspected memory leaks  (%d)", len(lk.SuspectedLeaks))))
	t := newTable([]string{"UNIT", "GROWTH/h", "R²", "SAMPLES"}, 1, 2, 3)
	for _, l := range lk.SuspectedLeaks {
		t.Row(trunc(l.UnitName, 44),
			ui.BadS.Render(humanBytes(int64(l.SlopeBytesPerHour))+"/h"),
			fmt.Sprintf("%.2f", l.RSquared), fmt.Sprintf("%d", l.Samples))
	}
	fmt.Fprintln(w, t)
}

func renderDeps(r *types.SystemReport, w io.Writer) {
	if d := r.DependencyAnalysis; d != nil {
		var lines []string
		for _, fu := range d.FailedUnitDependencies {
			var prob []string
			for _, dep := range fu.Dependencies {
				if dep.IsProblematic {
					prob = append(prob, ui.BadS.Render(dep.Name))
				}
			}
			if len(prob) > 0 {
				lines = append(lines, fmt.Sprintf("  %s → %s", fu.UnitName, strings.Join(prob, ", ")))
			}
		}
		if len(lines) > 0 {
			fmt.Fprintln(w, ui.Section("Dependencies of failed units"))
			fmt.Fprintln(w, strings.Join(lines, "\n"))
		}
	}
	if fd := r.FullDependencyAnalysis; fd != nil && len(fd.DetectedCycles) > 0 {
		fmt.Fprintln(w, ui.Section(fmt.Sprintf("Dependency cycles  (%d)", len(fd.DetectedCycles))))
		arrow := ui.DimS.Render(" → ")
		for _, c := range fd.DetectedCycles {
			fmt.Fprintf(w, "  %s%s%s\n", strings.Join(c, arrow), arrow, ui.BadS.Render(c[0]))
		}
	}
}

func renderLLM(r *types.SystemReport, w io.Writer) {
	l := r.LLMAnalysis
	if l == nil {
		return
	}
	if l.Error != "" {
		fmt.Fprintln(w, ui.Section("LLM synthesis"))
		fmt.Fprintf(w, "  %s %s\n", ui.BadS.Render("error:"), l.Error)
		return
	}
	if l.Synthesis == "" {
		return
	}
	fmt.Fprintln(w, ui.Section(fmt.Sprintf("LLM synthesis  (%s / %s)", l.ProviderUsed, l.ModelUsed)))
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder(), false, false, false, true).
		BorderForeground(ui.Accent).PaddingLeft(2).
		Render(strings.TrimSpace(l.Synthesis))
	fmt.Fprintln(w, box)
}
