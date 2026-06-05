package tui

import (
	"testing"

	"github.com/charmbracelet/lipgloss"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/ui"
)

// Regression guard: cell()/rowLine() must pad on *visible* width, so a row of
// ANSI-styled cells lines up with a plain one (the old %Ns formatting counted
// escape bytes and skewed every colored column).
func TestRowLineAlignment(t *testing.T) {
	plain := rowLine([]string{"unit", "1", "2", "3", "4", "5", "6", "7", "8", ""})
	styled := rowLine([]string{
		redStyle.Render("a-really-long-unit-name-that-overflows"),
		ui.WarnS.Render("99.9"), "10.0 GiB", ui.GoodS.Render("1.2 GiB↑"),
		"512 MiB", ui.BadS.Render("95%"), "1/s/2/s", "42",
		ui.DimS.Render("7"), redStyle.Render("LEAK?"),
	})

	want := len(cols) - 1 // single-space gutters
	for _, c := range cols {
		want += c.w
	}
	if got := lipgloss.Width(plain); got != want {
		t.Fatalf("plain row width = %d, want %d", got, want)
	}
	if got := lipgloss.Width(styled); got != want {
		t.Fatalf("styled row width = %d, want %d (ANSI miscounted)", got, want)
	}
}
