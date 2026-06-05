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

// JSONSingle returns a single-unit report as indented JSON.
func JSONSingle(r *types.SingleUnitReport) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// SingleUnit writes a styled focused report for one unit (analyze-unit).
func SingleUnit(r *types.SingleUnitReport, w io.Writer) {
	if r.AnalysisError != "" {
		fmt.Fprintf(w, "%s %s\n", ui.BadS.Render("error:"), r.AnalysisError)
		return
	}
	u := r.UnitInfo
	name := "unit"
	if u != nil {
		name = u.Name
	}
	title := lipgloss.NewStyle().Bold(true).Foreground(ui.Accent).Render(name)
	fmt.Fprintln(w, lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).BorderForeground(ui.Accent).Padding(0, 1).Render(title))

	if u != nil {
		st := ui.GoodS
		switch {
		case u.ActiveState == "failed":
			st = ui.BadS
		case u.IsFlapping || u.IsProblematicSocket || u.IsProblematicTimer:
			st = ui.WarnS
		}
		fmt.Fprintf(w, "%s %s\n", ui.CyanS.Render("state"),
			st.Render(fmt.Sprintf("%s / %s / %s", u.LoadState, u.ActiveState, u.SubState)))
		if u.Description != "" {
			fmt.Fprintf(w, "%s %s\n", ui.CyanS.Render("desc "), u.Description)
		}
		if u.ErrorMessage != "" {
			fmt.Fprintf(w, "  %s %s\n", ui.WarnS.Render("⚠"), u.ErrorMessage)
		}
	}

	if ru := r.ResourceUsage; ru != nil {
		fmt.Fprintln(w, ui.Section("Resources"))
		kv := [][2]string{}
		if ru.MemoryCurrentByte != nil {
			kv = append(kv, [2]string{"Memory", humanBytes(*ru.MemoryCurrentByte)})
		}
		if ru.MemoryAnonBytes != nil {
			kv = append(kv, [2]string{"Anon", humanBytes(*ru.MemoryAnonBytes)})
		}
		if ru.MemoryMaxBytes != nil {
			kv = append(kv, [2]string{"Limit", humanBytes(*ru.MemoryMaxBytes)})
		}
		if ru.TasksCurrent != nil {
			kv = append(kv, [2]string{"Tasks", fmt.Sprintf("%d", *ru.TasksCurrent)})
		}
		if ru.CPUUsageNsec != nil {
			kv = append(kv, [2]string{"CPU time", fmt.Sprintf("%.1fs", float64(*ru.CPUUsageNsec)/1e9)})
		}
		for _, p := range kv {
			fmt.Fprintf(w, "  %s %s\n", ui.CyanS.Render(fmt.Sprintf("%-9s", p[0])), p[1])
		}
		if ru.Error != "" {
			fmt.Fprintf(w, "  %s\n", ui.WarnS.Render(ru.Error))
		}
	}

	if d := r.DependencyInfo; d != nil && len(d.Dependencies) > 0 {
		fmt.Fprintln(w, ui.Section("Dependencies"))
		t := newTable([]string{"", "DEPENDENCY", "TYPE", "STATE"})
		for _, dep := range d.Dependencies {
			mark := ui.GoodS.Render("•")
			if dep.IsProblematic {
				mark = ui.BadS.Render("✗")
			}
			t.Row(mark, trunc(dep.Name, 40), dep.Type,
				fmt.Sprintf("%s/%s", dep.CurrentLoadState, dep.CurrentActiveState))
		}
		fmt.Fprintln(w, t)
	}

	if u != nil && len(u.RecentLogs) > 0 {
		fmt.Fprintln(w, ui.Section("Recent logs"))
		for _, line := range u.RecentLogs {
			fmt.Fprintln(w, ui.DimS.Render("  "+line))
		}
	}
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

// themedTable builds a rounded table whose header row is bold in the given
// accent color; columns in rightCols are right-aligned (numeric).
func themedTable(accent lipgloss.Color, headers []string, rightCols ...int) *table.Table {
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
				st = st.Bold(true).Foreground(accent)
			}
			return st
		})
}

// newTable is the default accent-headed table.
func newTable(headers []string, rightCols ...int) *table.Table {
	return themedTable(ui.Accent, headers, rightCols...)
}

func stateLAS(u types.UnitHealthInfo) string {
	return fmt.Sprintf("%s/%s/%s", orDash(u.LoadState), orDash(u.ActiveState), orDash(u.SubState))
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// lastLog returns the most recent journal line for a unit, trimmed of its
// "TIMESTAMP HOST " prefix and truncated, for a compact table cell.
func lastLog(u types.UnitHealthInfo) string {
	if len(u.RecentLogs) == 0 {
		return ui.DimS.Render("—")
	}
	line := u.RecentLogs[len(u.RecentLogs)-1]
	if parts := strings.SplitN(line, " ", 3); len(parts) == 3 {
		line = parts[2] // drop "<iso-ts> <host> "
	}
	return ui.DimS.Render(trunc(line, 48))
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
	renderEBPF(r, w)
	renderLLM(r, w)
}

func renderEBPF(r *types.SystemReport, w io.Writer) {
	e := r.EBPFAnalysis
	if e == nil {
		return
	}
	fmt.Fprintln(w, ui.Section("eBPF process tracing"))
	if e.Error != "" {
		fmt.Fprintf(w, "  %s %s\n", ui.DimS.Render("unavailable:"), e.Error)
		return
	}
	if len(e.UnitStats) == 0 {
		fmt.Fprintln(w, ui.DimS.Render("  no process activity captured in the window"))
		return
	}
	t := themedTable(ui.Accent, []string{"UNIT", "EXEC", "EXIT", "ABNORMAL", "OOM", "KILLED", "TOP CMD"}, 1, 2, 3, 4, 5)
	const limit = 15
	for i, s := range e.UnitStats {
		if i >= limit {
			break
		}
		abN := s.ExitNonzero + s.ExitSignaled
		abnormal := fmt.Sprintf("%d", abN)
		switch {
		case s.ExitSignaled > 0:
			abnormal = ui.BadS.Render(fmt.Sprintf("%d ⚑sig%d", abN, s.LastSignal))
		case s.ExitNonzero > 0:
			abnormal = ui.WarnS.Render(fmt.Sprintf("%d ⚑rc%d", abN, s.LastExitCode))
		}
		oom := "0"
		if s.OOMKills > 0 {
			oom = ui.BadS.Render(fmt.Sprintf("%d", s.OOMKills))
		}
		killed := fmt.Sprintf("%d", s.SigKillRcvd+s.SigTermRcvd)
		if s.SigKillRcvd > 0 {
			killed = ui.WarnS.Render(killed)
		}
		t.Row(trunc(s.Unit, 32), fmt.Sprintf("%d", s.Execs), fmt.Sprintf("%d", s.Exits),
			abnormal, oom, killed, trunc(s.TopCommand, 16))
	}
	fmt.Fprintln(w, t)
	if len(e.UnitStats) > limit {
		fmt.Fprintln(w, ui.DimS.Render(fmt.Sprintf("  +%d more units", len(e.UnitStats)-limit)))
	}
}

func renderHealth(r *types.SystemReport, w io.Writer) {
	h := r.HealthAnalysis
	if h == nil {
		return
	}
	fmt.Fprintln(w, ui.Section("Service Health"))
	fmt.Fprintf(w, "  %s %d failed   %s %d flapping   %s %d sockets   %s %d timers   %s %d units\n",
		ui.Dot(ui.BadS), len(h.FailedUnits), ui.Dot(ui.WarnS), len(h.FlappingUnits),
		ui.Dot(ui.OrangeS), len(h.ProblematicSockets), ui.Dot(ui.CyanS), len(h.ProblematicTimers),
		ui.Dot(ui.GoodS), h.AllUnitsCount)

	if len(h.FailedUnits) > 0 {
		fmt.Fprintln(w, ui.Title(fmt.Sprintf("Failed Units (%d)", len(h.FailedUnits)), ui.Bad))
		t := themedTable(ui.Bad, []string{"UNIT", "LOAD", "ACTIVE", "SUB", "DETAIL / RESULT", "RECENT"})
		for _, u := range h.FailedUnits {
			detail := u.Details["Result"]
			if detail == "" {
				detail = u.Description
			}
			t.Row(trunc(u.Name, 34), orDash(u.LoadState), orDash(u.ActiveState), orDash(u.SubState),
				trunc(detail, 24), lastLog(u))
		}
		fmt.Fprintln(w, t)
	}
	if len(h.FlappingUnits) > 0 {
		fmt.Fprintln(w, ui.Title(fmt.Sprintf("Flapping Units (%d)", len(h.FlappingUnits)), ui.Warn))
		t := themedTable(ui.Warn, []string{"UNIT", "RESTARTS", "STATE (L/A/S)", "RECENT"}, 1)
		for _, u := range h.FlappingUnits {
			t.Row(trunc(u.Name, 34), orDash(u.Details["NRestarts"]), stateLAS(u), lastLog(u))
		}
		fmt.Fprintln(w, t)
	}
	if len(h.ProblematicSockets) > 0 {
		fmt.Fprintln(w, ui.Title(fmt.Sprintf("Problematic Sockets (%d)", len(h.ProblematicSockets)), ui.Orange))
		t := themedTable(ui.Orange, []string{"SOCKET", "STATE (L/A/S)", "ISSUE", "RECENT"})
		for _, u := range h.ProblematicSockets {
			t.Row(trunc(u.Name, 30), stateLAS(u), trunc(u.ErrorMessage, 32), lastLog(u))
		}
		fmt.Fprintln(w, t)
	}
	if len(h.ProblematicTimers) > 0 {
		fmt.Fprintln(w, ui.Title(fmt.Sprintf("Problematic Timers (%d)", len(h.ProblematicTimers)), ui.Cyan))
		t := themedTable(ui.Cyan, []string{"TIMER", "STATE (L/A/S)", "ISSUE", "RECENT"})
		for _, u := range h.ProblematicTimers {
			t.Row(trunc(u.Name, 30), stateLAS(u), trunc(u.ErrorMessage, 32), lastLog(u))
		}
		fmt.Fprintln(w, t)
	}
	fmt.Fprintln(w, ui.DimS.Render(fmt.Sprintf("  analyzed %d units", h.AllUnitsCount)))
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
	t := themedTable(ui.Warn, []string{"UNIT", "SCORE", "METHOD", "CONTRIBUTING"}, 1)
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
	t := themedTable(ui.Bad, []string{"UNIT", "GROWTH/h", "R²", "SAMPLES"}, 1, 2, 3)
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
