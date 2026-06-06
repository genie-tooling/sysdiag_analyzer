// Package boot collects boot timing, blame and critical-chain via systemd-analyze.
package boot

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

// systemd prints compound durations: "10.951s", "696ms", "1min 21.085s", "2min 389ms".
const timeToken = `\d+(?:\.\d+)?\s*(?:h|min|ms|us|s)`

var timeValue = `(?:` + timeToken + `)(?:\s+` + timeToken + `)*`

var bootLineRe = regexp.MustCompile(
	`Startup finished in\s+` +
		`(?:(?P<firmware>` + timeValue + `)\s+\(firmware\)\s*\+?\s*)?` +
		`(?:(?P<loader>` + timeValue + `)\s+\(loader\)\s*\+?\s*)?` +
		`(?:(?P<kernel>` + timeValue + `)\s+\(kernel\)\s*\+?\s*)?` +
		`(?:(?P<initrd>` + timeValue + `)\s+\(initrd\)\s*\+?\s*)?` +
		`(?:(?P<userspace>` + timeValue + `)\s+\(userspace\)\s*\+?\s*)?` +
		`\s*=\s+(?P<total>` + timeValue + `)`,
)

var (
	ccTimeAtRe    = regexp.MustCompile(`@[\d.]+\s*\w*`)
	ccTimeDeltaRe = regexp.MustCompile(`\+[\d.]+\s*\w*`)
	treeChars     = "└├│`─- \t"
)

func runC(args ...string) (string, error) {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "LANG=C", "LC_ALL=C")
	out, err := cmd.Output()
	return string(out), err
}

// Analyze runs systemd-analyze {time, blame, critical-chain} and parses them.
func Analyze() *types.BootAnalysisResult {
	res := &types.BootAnalysisResult{
		Blame:         []types.BootBlameItem{},
		CriticalChain: []types.CriticalChainItem{},
	}
	// The three systemd-analyze subprocesses are independent — run concurrently.
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); res.Times = parseTimes() }()
	go func() { defer wg.Done(); res.Blame, res.BlameError = parseBlame() }()
	go func() { defer wg.Done(); res.CriticalChain, res.CriticalChainError = parseCriticalChain() }()
	wg.Wait()
	return res
}

func parseTimes() *types.BootTimes {
	t := &types.BootTimes{}
	out, err := runC("systemd-analyze")
	if err != nil {
		t.Error = "systemd-analyze failed: " + err.Error()
		return t
	}
	for _, line := range strings.Split(out, "\n") {
		m := bootLineRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		for i, name := range bootLineRe.SubexpNames() {
			v := strings.TrimSpace(m[i])
			switch name {
			case "firmware":
				t.Firmware = v
			case "loader":
				t.Loader = v
			case "kernel":
				t.Kernel = v
			case "initrd":
				t.Initrd = v
			case "userspace":
				t.Userspace = v
			case "total":
				t.Total = v
			}
		}
		if t.Total != "" {
			return t
		}
	}
	t.Error = "Failed to determine boot times from output."
	return t
}

func parseBlame() ([]types.BootBlameItem, string) {
	out, err := runC("systemd-analyze", "blame", "--no-pager")
	if err != nil {
		return nil, "systemd-analyze blame failed: " + err.Error()
	}
	var items []types.BootBlameItem
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// Time may contain a space ("1min 21.085s"); unit is the last field.
		unit := fields[len(fields)-1]
		t := strings.Join(fields[:len(fields)-1], " ")
		items = append(items, types.BootBlameItem{Time: t, Unit: unit})
	}
	return items, ""
}

func parseCriticalChain() ([]types.CriticalChainItem, string) {
	out, err := runC("systemd-analyze", "critical-chain", "--no-pager")
	if err != nil {
		return nil, "systemd-analyze critical-chain failed: " + err.Error()
	}
	var items []types.CriticalChainItem
	for _, raw := range strings.Split(out, "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		low := strings.ToLower(raw)
		if strings.Contains(low, "the time") || strings.Contains(low, "the unit") ||
			strings.Contains(low, "character") {
			continue // header lines
		}
		indent := len(raw) - len(strings.TrimLeft(raw, treeChars))
		rest := raw
		var timeAt, timeDelta string
		if m := ccTimeAtRe.FindString(rest); m != "" {
			timeAt = strings.TrimSpace(m)
			rest = strings.Replace(rest, m, "", 1)
		}
		if m := ccTimeDeltaRe.FindString(rest); m != "" {
			timeDelta = strings.TrimSpace(m)
			rest = strings.Replace(rest, m, "", 1)
		}
		unit := strings.Trim(rest, treeChars)
		unit = strings.TrimSpace(unit)
		if unit == "" {
			continue
		}
		items = append(items, types.CriticalChainItem{
			Unit: unit, TimeAt: timeAt, TimeDelta: timeDelta, Indent: indent,
		})
	}
	return items, ""
}
