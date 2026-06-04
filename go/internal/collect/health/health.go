// Package health identifies failed and flapping units, mirroring modules/health.py.
package health

import (
	"context"
	"strconv"
	"strings"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/systemd"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

const flappingRestartThreshold = 3 // FLAPPING_RESTART_THRESHOLD in health.py

// Analyze classifies the provided units into failed/flapping (sockets/timers TODO).
func Analyze(_ context.Context, units []types.UnitHealthInfo) *types.HealthAnalysisResult {
	res := &types.HealthAnalysisResult{
		AllUnitsCount:      len(units),
		FailedUnits:        []types.UnitHealthInfo{},
		FlappingUnits:      []types.UnitHealthInfo{},
		ProblematicSockets: []types.UnitHealthInfo{},
		ProblematicTimers:  []types.UnitHealthInfo{},
	}

	serviceNames := make([]string, 0, len(units))
	for _, u := range units {
		if strings.HasSuffix(u.Name, ".service") {
			serviceNames = append(serviceNames, u.Name)
		}
	}
	props := systemd.ShowProperties(serviceNames, []string{"NRestarts", "Result", "MainPID"})

	for i := range units {
		u := &units[i]
		if kv, ok := props[u.Name]; ok {
			u.Details = kv
		}
		if u.ActiveState == "failed" {
			u.IsFailed = true
			res.FailedUnits = append(res.FailedUnits, *u)
		}
		if kv, ok := props[u.Name]; ok {
			if nr, err := strconv.Atoi(kv["NRestarts"]); err == nil && nr >= flappingRestartThreshold {
				u.IsFlapping = true
				res.FlappingUnits = append(res.FlappingUnits, *u)
			}
		}
	}
	return res
}
