// Package features extracts per-(unit,timestamp) resource records from reports,
// the input to the statistical + leak detectors (mirrors features.py's resource rows).
package features

import (
	"time"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

// Feature is one unit's resource sample at a report timestamp.
type Feature struct {
	Unit       string
	TS         float64 // epoch seconds
	CPUNsec    *int64
	MemAnon    *int64
	MemCurrent *int64
	IORead     *int64
	IOWrite    *int64
	Tasks      *int64
	MajFault   *int64
}

func parseTS(s string) (float64, bool) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999-07:00", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return float64(t.UnixNano()) / 1e9, true
		}
	}
	return 0, false
}

// Extract flattens the resource_analysis rows of each report into Features.
func Extract(reports []*types.SystemReport) []Feature {
	var out []Feature
	for _, r := range reports {
		if r == nil || r.ResourceAnalysis == nil {
			continue
		}
		ts, ok := parseTS(r.Timestamp)
		if !ok {
			continue
		}
		for i := range r.ResourceAnalysis.UnitUsage {
			u := &r.ResourceAnalysis.UnitUsage[i]
			out = append(out, Feature{
				Unit: u.Name, TS: ts,
				CPUNsec: u.CPUUsageNsec, MemAnon: u.MemoryAnonBytes,
				MemCurrent: u.MemoryCurrentByte, IORead: u.IOReadBytes,
				IOWrite: u.IOWriteBytes, Tasks: u.TasksCurrent,
				MajFault: u.MemoryPgMajfault,
			})
		}
	}
	return out
}
