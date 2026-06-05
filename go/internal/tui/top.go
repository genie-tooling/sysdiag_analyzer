package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/collect/resources"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/config"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/systemd"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/ui"
)

const unitRefreshEvery = 10

var (
	titleStyle = ui.TitleS
	colStyle   = lipgloss.NewStyle().Bold(true).Foreground(ui.Accent)
	redStyle   = ui.BadS
	dimStyle   = ui.DimS
)

// column layout: width and right-alignment for each top column.
type col struct {
	title string
	w     int
	right bool
}

var cols = []col{
	{"UNIT / SCOPE", 32, false},
	{"CPU%", 6, true},
	{"MEM", 10, true},
	{"ANON", 11, true},
	{"LIMIT", 9, true},
	{"%LIM", 5, true},
	{"IO R / W", 19, true},
	{"TASKS", 6, true},
	{"FD", 5, true},
	{"FLAGS", 6, false},
}

// cell pads s to width w (visible width, ANSI-aware) without wrapping, so
// pre-colored cells stay aligned — fmt's %Ns would miscount escape bytes.
func cell(w int, right bool, s string) string {
	st := lipgloss.NewStyle().Width(w).MaxWidth(w)
	if right {
		st = st.Align(lipgloss.Right)
	}
	return st.Render(s)
}

// rowLine joins cells (one per column) with a single space gutter.
func rowLine(cells []string) string {
	out := make([]string, len(cols))
	for i := range cols {
		out[i] = cell(cols[i].w, cols[i].right, cells[i])
	}
	return strings.Join(out, " ")
}

type collector struct {
	cfg       config.Config
	ctx       context.Context
	state     *State
	pathCache map[string]string
	units     []types.UnitHealthInfo
	tickN     int
}

type displayRow struct {
	u  types.UnitResourceUsage
	d  Derived
	fd *int
}

type snapshotMsg struct {
	sys            *types.SystemResourceUsage
	rows           []displayRow
	netUp, netDown *float64
	failed         map[string]bool
	leaks          int
}

type collectTrigger struct{}

func nowSec() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func (c *collector) snapshot(sortKey string, count int) tea.Msg {
	c.tickN++
	if c.units == nil || c.tickN%unitRefreshEvery == 1 {
		if u, err := systemd.ListUnits(c.ctx); err == nil && len(u) > 0 {
			c.units = u
			c.pathCache = map[string]string{}
		}
	}
	sys := resources.SystemUsage()
	usages := resources.CollectUnitUsage(c.units, c.pathCache)
	now := nowSec()
	derived := c.state.Update(usages, now)
	up, down := c.state.NetRate(sys, now)

	failed := map[string]bool{}
	for _, u := range c.units {
		if u.ActiveState == "failed" {
			failed[u.Name] = true
		}
	}
	leaks := 0
	for _, d := range derived {
		if d.Leaking {
			leaks++
		}
	}

	SortUsages(usages, sortKey)
	if len(usages) > count {
		usages = usages[:count]
	}
	rows := make([]displayRow, len(usages))
	for i, u := range usages {
		rows[i] = displayRow{u: u, d: derived[u.Name]}
		if u.CgroupPath != "" {
			rows[i].fd = resources.CgroupFDCount(u.CgroupPath)
		}
	}
	return snapshotMsg{sys: sys, rows: rows, netUp: up, netDown: down, failed: failed, leaks: leaks}
}

type model struct {
	c        *collector
	interval time.Duration
	sortKey  string
	count    int
	snap     snapshotMsg
	ready    bool
}

func (m model) Init() tea.Cmd {
	return func() tea.Msg { return m.c.snapshot(m.sortKey, m.count) }
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case snapshotMsg:
		m.snap = msg
		m.ready = true
		return m, tea.Tick(m.interval, func(time.Time) tea.Msg { return collectTrigger{} })
	case collectTrigger:
		sk, cnt := m.sortKey, m.count
		c := m.c
		return m, func() tea.Msg { return c.snapshot(sk, cnt) }
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "m":
			m.sortKey = "mem"
		case "c":
			m.sortKey = "cpu"
		case "i":
			m.sortKey = "io"
		case "l":
			m.sortKey = "limit"
		}
		return m, nil
	}
	return m, nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func ratePctStr(p *float64) string {
	if p == nil {
		return dimStyle.Render("—")
	}
	return fmt.Sprintf("%.1f", *p)
}

func rateStr(p *float64) string {
	if p == nil {
		return "—"
	}
	return humanBytes(int64(*p)) + "/s"
}

func sysPct(label string, p *float64) string {
	if p == nil {
		return label + " " + dimStyle.Render("n/a")
	}
	return label + " " + ui.PctStyle(*p).Render(fmt.Sprintf("%.0f%%", *p))
}

func (m model) View() string {
	if !m.ready {
		return "collecting…"
	}
	var b strings.Builder
	s := m.snap

	// Title bar: chip + system gauges + net + failed/leak counts.
	var stats []string
	if s.sys != nil {
		stats = append(stats, sysPct("CPU", s.sys.CPUPercent), sysPct("Mem", s.sys.MemPercent), sysPct("Swap", s.sys.SwapPercent))
	}
	if s.netUp != nil && s.netDown != nil {
		stats = append(stats, ui.CyanS.Render(fmt.Sprintf("Net ↑%s/s ↓%s/s", humanBytes(int64(*s.netUp)), humanBytes(int64(*s.netDown)))))
	}
	failedStr := fmt.Sprintf("%d failed", len(s.failed))
	if len(s.failed) > 0 {
		failedStr = redStyle.Render(failedStr)
	} else {
		failedStr = ui.GoodS.Render(failedStr)
	}
	stats = append(stats, failedStr)
	if s.leaks > 0 {
		stats = append(stats, redStyle.Render(fmt.Sprintf("⚠ %d leak?", s.leaks)))
	}
	sep := dimStyle.Render("  ·  ")
	b.WriteString(titleStyle.Render("sysdiag top") + "  " + strings.Join(stats, sep) + "\n")
	b.WriteString(dimStyle.Render(fmt.Sprintf("sort: %s   ·   keys: q quit · m/c/i/l sort by mem/cpu/io/limit", m.sortKey)) + "\n")

	// Column header.
	heads := make([]string, len(cols))
	for i, c := range cols {
		heads[i] = colStyle.Render(c.title)
	}
	b.WriteString(rowLine(heads) + "\n")
	b.WriteString(dimStyle.Render(strings.Repeat("─", lipgloss.Width(rowLine(heads)))) + "\n")

	for _, r := range s.rows {
		u, d := r.u, r.d
		limit, pct := dimStyle.Render("none"), dimStyle.Render("—")
		if u.MemoryMaxBytes != nil {
			limit = humanBytes(*u.MemoryMaxBytes)
			p := 0.0
			if v := u.MemoryPercentOfLimit(); v != nil {
				p = *v
			}
			pct = ui.PctStyle(p).Render(fmt.Sprintf("%.0f%%", p))
		}
		name := trunc(u.Name, cols[0].w)
		if s.failed[u.Name] {
			name = redStyle.Render(name)
		}
		anon := dimStyle.Render("—")
		if u.MemoryAnonBytes != nil {
			anon = humanBytes(*u.MemoryAnonBytes)
			if d.MemTrend != "" {
				anon += trendGlyph(d.MemTrend)
			}
		}
		fd := dimStyle.Render("—")
		if r.fd != nil {
			fd = fmt.Sprintf("%d", *r.fd)
		}
		flags := ""
		if d.Leaking {
			flags = redStyle.Render("LEAK?")
		}
		tasks := dimStyle.Render("—")
		if u.TasksCurrent != nil {
			tasks = fmt.Sprintf("%d", *u.TasksCurrent)
		}
		io := rateStr(d.IOReadRate) + dimStyle.Render("/") + rateStr(d.IOWriteRate)
		b.WriteString(rowLine([]string{
			name, ratePctStr(d.CPUPct), humanBytes(memCur(u)), anon, limit, pct, io, tasks, fd, flags,
		}) + "\n")
	}
	return b.String()
}

// trendGlyph colorizes a rising/falling/flat trend marker.
func trendGlyph(t string) string {
	switch {
	case strings.ContainsAny(t, "↑▲"):
		return ui.WarnS.Render(t)
	case strings.ContainsAny(t, "↓▼"):
		return ui.GoodS.Render(t)
	default:
		return dimStyle.Render(t)
	}
}

// trunc shortens s to n visible columns with an ellipsis.
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

func memCur(u types.UnitResourceUsage) int64 {
	if u.MemoryCurrentByte == nil {
		return 0
	}
	return *u.MemoryCurrentByte
}

// Run launches the live top view until the user quits.
func Run(ctx context.Context, cfg config.Config, interval time.Duration, sortKey string, count int) error {
	switch sortKey {
	case "mem", "cpu", "io", "limit":
	default:
		sortKey = "mem"
	}
	c := &collector{cfg: cfg, ctx: ctx, state: NewState(), pathCache: map[string]string{}}
	m := model{c: c, interval: interval, sortKey: sortKey, count: count}
	_, err := tea.NewProgram(m, tea.WithAltScreen(), tea.WithContext(ctx)).Run()
	return err
}
