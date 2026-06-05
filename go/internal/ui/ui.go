// Package ui holds the shared color palette and small render helpers used by
// both the report renderer and the live `top` TUI, so the two share one
// modern, colorful look. Colors are truecolor hex; lipgloss automatically
// degrades them on 256-color/ANSI terminals and strips them when stdout is
// not a TTY (e.g. piped to a file).
package ui

import "github.com/charmbracelet/lipgloss"

// A Tokyo-Night-inspired palette: easy on the eyes on a dark terminal.
var (
	Accent = lipgloss.Color("#7AA2F7") // blue   — titles, headers, structure
	Cyan   = lipgloss.Color("#7DCFFF") // cyan   — secondary accent
	Good   = lipgloss.Color("#9ECE6A") // green  — healthy / low
	Warn   = lipgloss.Color("#E0AF68") // amber  — warning / elevated
	Bad    = lipgloss.Color("#F7768E") // red    — failed / critical / leak
	Muted  = lipgloss.Color("#565F89") // grey   — secondary / "n/a"
)

// Reusable styles.
var (
	HeaderS = lipgloss.NewStyle().Bold(true).Foreground(Accent)
	TitleS  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#1A1B26")).Background(Accent).Padding(0, 1)
	DimS    = lipgloss.NewStyle().Foreground(Muted)
	GoodS   = lipgloss.NewStyle().Foreground(Good)
	WarnS   = lipgloss.NewStyle().Foreground(Warn)
	BadS    = lipgloss.NewStyle().Foreground(Bad)
	CyanS   = lipgloss.NewStyle().Foreground(Cyan)
	BorderS = lipgloss.NewStyle().Foreground(Muted)
)

// Section renders a section heading: an accent bar followed by a bold label.
func Section(label string) string {
	return lipgloss.NewStyle().Foreground(Accent).Render("▌ ") + HeaderS.Render(label)
}

// PctStyle picks a severity style for a 0..100 percentage (>=90 red, >=75 amber, else green).
func PctStyle(p float64) lipgloss.Style {
	switch {
	case p >= 90:
		return BadS
	case p >= 75:
		return WarnS
	default:
		return GoodS
	}
}

// Dot returns a colored "●" for the given severity style.
func Dot(s lipgloss.Style) string { return s.Render("●") }
