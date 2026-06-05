// Package health identifies failed, flapping, and problematic socket/timer
// units, mirroring modules/health.py.
package health

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/systemd"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

const flappingRestartThreshold = 3 // FLAPPING_RESTART_THRESHOLD in health.py

const recentLogLines = 20

func hasAnySuffix(s string, sfx ...string) bool {
	for _, x := range sfx {
		if strings.HasSuffix(s, x) {
			return true
		}
	}
	return false
}

func orQ(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

// Analyze classifies units into failed / flapping / problematic-socket /
// problematic-timer, fetching recent logs for each problematic unit.
func Analyze(_ context.Context, units []types.UnitHealthInfo) *types.HealthAnalysisResult {
	res := &types.HealthAnalysisResult{
		AllUnitsCount:      len(units),
		FailedUnits:        []types.UnitHealthInfo{},
		FlappingUnits:      []types.UnitHealthInfo{},
		ProblematicSockets: []types.UnitHealthInfo{},
		ProblematicTimers:  []types.UnitHealthInfo{},
	}

	// Fetch details once for every unit that needs them (failed, or service/socket/timer).
	var needNames []string
	for _, u := range units {
		if u.ActiveState == "failed" || hasAnySuffix(u.Name, ".service", ".socket", ".timer") {
			needNames = append(needNames, u.Name)
		}
	}
	props := systemd.ShowProperties(needNames, []string{"NRestarts", "Result", "MainPID", "Refused"})

	for i := range units {
		u := &units[i]
		if kv, ok := props[u.Name]; ok {
			u.Details = kv
		}

		// 1. Failed (any unit type) — takes precedence.
		if u.ActiveState == "failed" {
			u.IsFailed = true
			u.RecentLogs = systemd.UnitLogs(u.Name, recentLogLines)
			res.FailedUnits = append(res.FailedUnits, *u)
			continue
		}

		// 2. Flapping (.service, NRestarts >= threshold).
		if strings.HasSuffix(u.Name, ".service") {
			if nr, err := strconv.Atoi(u.Details["NRestarts"]); err == nil && nr >= flappingRestartThreshold {
				u.IsFlapping = true
				u.RecentLogs = systemd.UnitLogs(u.Name, recentLogLines)
				res.FlappingUnits = append(res.FlappingUnits, *u)
				continue
			}
		}

		// 3. Problematic socket (Refused, or unexpected active/sub state).
		if strings.HasSuffix(u.Name, ".socket") {
			if bad, msg := socketProblem(u.ActiveState, u.SubState, u.Details["Refused"]); bad {
				u.IsProblematicSocket = true
				u.ErrorMessage = msg
				u.RecentLogs = systemd.UnitLogs(u.Name, recentLogLines)
				res.ProblematicSockets = append(res.ProblematicSockets, *u)
				continue
			}
		}

		// 4. Problematic timer (last Result != success, or unexpected state).
		if strings.HasSuffix(u.Name, ".timer") {
			if bad, msg := timerProblem(u.ActiveState, u.SubState, u.Details["Result"]); bad {
				u.IsProblematicTimer = true
				u.ErrorMessage = msg
				u.RecentLogs = systemd.UnitLogs(u.Name, recentLogLines)
				res.ProblematicTimers = append(res.ProblematicTimers, *u)
				continue
			}
		}
	}
	return res
}

// socketProblem flags a socket that is refusing connections or in an unexpected
// state (active but not listening/running, or neither active nor inactive).
func socketProblem(active, sub, refused string) (bool, string) {
	isRefused := strings.EqualFold(refused, "yes") || strings.EqualFold(refused, "true")
	badState := (active != "active" && active != "inactive") ||
		(active == "active" && sub != "listening" && sub != "running")
	switch {
	case isRefused:
		return true, "Socket is refusing connections (Refused=yes)."
	case badState:
		return true, fmt.Sprintf("Socket in potentially problematic state: %s/%s", orQ(active), orQ(sub))
	}
	return false, ""
}

// timerProblem flags a timer whose last run failed or that is in an unexpected
// state (active but not waiting/running, or neither active nor inactive).
func timerProblem(active, sub, result string) (bool, string) {
	if result == "" {
		result = "success"
	}
	badState := (active != "active" && active != "inactive") ||
		(active == "active" && sub != "waiting" && sub != "running")
	switch {
	case result != "success":
		return true, fmt.Sprintf("Timer last run resulted in '%s'.", result)
	case badState:
		return true, fmt.Sprintf("Timer in potentially problematic state: %s/%s", orQ(active), orQ(sub))
	}
	return false, ""
}
