// Package logs scans the journal (via journalctl) for OOM events and common
// error/warning patterns, mirroring modules/logs.py.
package logs

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

const (
	DefaultAnalysisLevel = 4 // WARNING and higher
	maxExampleMessages   = 3
)

var levelMap = map[int]string{
	0: "EMERG", 1: "ALERT", 2: "CRIT", 3: "ERR",
	4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG",
}

var oomPattern = regexp.MustCompile(`(?i)(Out of memory:|oom-killer:|memory cgroup out of memory)`)

// Ordered keys preserve match priority (first match wins, like the Python loop).
var errorKeys = []string{"segfault", "kernel-panic", "call-trace", "BUG:", "exception-trace", "hardware-error"}
var errorPatterns = map[string]*regexp.Regexp{
	"segfault":        regexp.MustCompile(`(?i)segfault.*ip\s+[0-9a-f]+.*sp\s+[0-9a-f]+.*error\s+\d+`),
	"kernel-panic":    regexp.MustCompile(`(?i)Kernel panic - not syncing:`),
	"call-trace":      regexp.MustCompile(`(?i)Call Trace:`),
	"BUG:":            regexp.MustCompile(`(?i)\bBUG:`),
	"exception-trace": regexp.MustCompile(`(?i)exception trace:`),
	"hardware-error":  regexp.MustCompile(`(?i)\b(Hardware Error|MCA:)`),
}

var warnKeys = []string{"i/o-error", "filesystem-readonly", "buffer-io-error", "task-blocked"}
var warnPatterns = map[string]*regexp.Regexp{
	"i/o-error":           regexp.MustCompile(`(?i)\b(I/O error|Input/output error)\b`),
	"filesystem-readonly": regexp.MustCompile(`(?i)Remounting filesystem read-only`),
	"buffer-io-error":     regexp.MustCompile(`(?i)Buffer I/O error`),
	"task-blocked":        regexp.MustCompile(`(?i)task .* blocked for more than \d+ seconds`),
}

// Analyze scans the journal. since (journalctl --since spec) overrides bootOffset when set.
func Analyze(bootOffset, minPriority int, since string) *types.LogAnalysisResult {
	res := &types.LogAnalysisResult{LogSource: "journalctl", DetectedPatterns: []types.LogPatternInfo{}}

	args := []string{}
	if since != "" {
		args = append(args, "--since", since)
	} else {
		args = append(args, fmt.Sprintf("-b%d", bootOffset))
	}
	args = append(args,
		fmt.Sprintf("-p%d..0", minPriority),
		"-o", "json", "--no-pager",
		"--output-fields=__REALTIME_TIMESTAMP,PRIORITY,MESSAGE,_SYSTEMD_UNIT,_PID",
	)
	out, err := exec.Command("journalctl", args...).Output()
	if err != nil {
		res.AnalysisError = "journalctl failed: " + err.Error()
		return res
	}

	counts := map[string]*types.LogPatternInfo{}
	var order []string
	add := func(ptype, key, level string, entry map[string]any) {
		pi, ok := counts[key]
		if !ok {
			pi = &types.LogPatternInfo{PatternType: ptype, PatternKey: key, Level: level, ExampleMessages: []string{}}
			counts[key] = pi
			order = append(order, key)
		}
		pi.Count++
		if len(pi.ExampleMessages) < maxExampleMessages {
			pi.ExampleMessages = append(pi.ExampleMessages, formatEntry(entry))
		}
	}

	total := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var entry map[string]any
		if json.Unmarshal([]byte(line), &entry) != nil {
			continue
		}
		total++
		msg := asString(entry["MESSAGE"])
		if msg == "" {
			continue
		}
		level := levelFromPriority(entry["PRIORITY"])
		switch {
		case oomPattern.MatchString(msg):
			add("OOM", "oom-killer", level, entry)
		default:
			matched := false
			for _, k := range errorKeys {
				if errorPatterns[k].MatchString(msg) {
					add("Error", k, level, entry)
					matched = true
					break
				}
			}
			if !matched {
				for _, k := range warnKeys {
					if warnPatterns[k].MatchString(msg) {
						add("Warning", k, level, entry)
						break
					}
				}
			}
		}
	}
	res.TotalEntriesAnalyzed = total
	for _, k := range order {
		res.DetectedPatterns = append(res.DetectedPatterns, *counts[k])
	}
	return res
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func levelFromPriority(v any) string {
	s := asString(v)
	if s == "" {
		return ""
	}
	if p, err := strconv.Atoi(s); err == nil {
		return levelMap[p]
	}
	return ""
}

func formatEntry(entry map[string]any) string {
	ts := "NoTimestamp"
	if usec, err := strconv.ParseInt(asString(entry["__REALTIME_TIMESTAMP"]), 10, 64); err == nil {
		ts = time.UnixMicro(usec).UTC().Format("2006-01-02T15:04:05.000")
	}
	level := levelFromPriority(entry["PRIORITY"])
	if level == "" {
		level = "UNK"
	}
	unit := asString(entry["_SYSTEMD_UNIT"])
	if unit == "" {
		unit = "system"
	}
	pid := asString(entry["_PID"])
	if pid == "" {
		pid = "-"
	}
	return fmt.Sprintf("%s [%s] %s(%s): %s", ts, level, unit, pid, asString(entry["MESSAGE"]))
}
