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
)

const unitRefreshEvery = 10

var (
	headerStyle = lipgloss.NewStyle().Bold(true)
	colStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	redStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	yellowStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	greenStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	dimStyle    = lipgloss.NewStyle().Faint(true)
)

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

func (m model) View() string {
	if !m.ready {
		return "collecting…"
	}
	var b strings.Builder
	s := m.snap
	parts := []string{"sort:" + m.sortKey}
	if s.sys != nil {
		if s.sys.CPUPercent != nil {
			parts = append(parts, fmt.Sprintf("CPU %.0f%%", *s.sys.CPUPercent))
		}
		if s.sys.MemPercent != nil {
			parts = append(parts, fmt.Sprintf("Mem %.0f%%", *s.sys.MemPercent))
		}
		if s.sys.SwapPercent != nil {
			parts = append(parts, fmt.Sprintf("Swap %.0f%%", *s.sys.SwapPercent))
		}
	}
	if s.netUp != nil && s.netDown != nil {
		parts = append(parts, fmt.Sprintf("Net ↑%s/s ↓%s/s", humanBytes(int64(*s.netUp)), humanBytes(int64(*s.netDown))))
	}
	parts = append(parts, fmt.Sprintf("failed:%d", len(s.failed)))
	if s.leaks > 0 {
		parts = append(parts, redStyle.Render(fmt.Sprintf("leaks?:%d", s.leaks)))
	}
	b.WriteString(headerStyle.Render("sysdiag top  ·  "+strings.Join(parts, "  ·  ")) + "\n")
	b.WriteString(dimStyle.Render("keys: q quit · m/c/i/l sort by mem/cpu/io/limit") + "\n\n")

	b.WriteString(colStyle.Render(fmt.Sprintf("%-34s %6s %9s %9s %8s %5s %16s %6s %6s %s",
		"UNIT / SCOPE", "CPU%", "MEM", "ANON", "LIMIT", "%LIM", "IO R/W", "TASKS", "FD", "FLAGS")) + "\n")

	for _, r := range s.rows {
		u, d := r.u, r.d
		limit, pct := dimStyle.Render("none"), dimStyle.Render("—")
		if u.MemoryMaxBytes != nil {
			limit = humanBytes(*u.MemoryMaxBytes)
			p := 0.0
			if v := u.MemoryPercentOfLimit(); v != nil {
				p = *v
			}
			st := greenStyle
			if p >= 90 {
				st = redStyle
			} else if p >= 75 {
				st = yellowStyle
			}
			pct = st.Render(fmt.Sprintf("%.0f%%", p))
		}
		name := u.Name
		if len(name) > 34 {
			name = name[:33] + "…"
		}
		if s.failed[u.Name] {
			name = redStyle.Render(name)
		}
		anon := "—"
		if u.MemoryAnonBytes != nil {
			anon = humanBytes(*u.MemoryAnonBytes)
		}
		if d.MemTrend != "" {
			anon += d.MemTrend
		}
		fd := dimStyle.Render("—")
		if r.fd != nil {
			fd = fmt.Sprintf("%d", *r.fd)
		}
		flags := ""
		if d.Leaking {
			flags = redStyle.Render("LEAK?")
		}
		tasks := "—"
		if u.TasksCurrent != nil {
			tasks = fmt.Sprintf("%d", *u.TasksCurrent)
		}
		b.WriteString(fmt.Sprintf("%-34s %6s %9s %9s %8s %5s %16s %6s %6s %s\n",
			name, ratePctStr(d.CPUPct), humanBytes(memCur(u)), anon, limit, pct,
			rateStr(d.IOReadRate)+"/"+rateStr(d.IOWriteRate), tasks, fd, flags))
	}
	return b.String()
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
