// Package resources collects system-wide (gopsutil) and per-unit cgroup v2
// resource usage, mirroring modules/resources.py.
package resources

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/systemd"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

const topN = 10

func pf(v float64) *float64 { return &v }
func pi(v int64) *int64     { return &v }

// SystemUsage gathers system-wide CPU/mem/swap/disk/net via gopsutil.
func SystemUsage() *types.SystemResourceUsage {
	u := &types.SystemResourceUsage{}
	var errs []string
	if pct, err := cpu.Percent(100*time.Millisecond, false); err == nil && len(pct) > 0 {
		u.CPUPercent = pf(pct[0])
	} else if err != nil {
		errs = append(errs, "cpu: "+err.Error())
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		u.MemTotalBytes = pi(int64(vm.Total))
		u.MemAvailBytes = pi(int64(vm.Available))
		u.MemPercent = pf(vm.UsedPercent)
	} else {
		errs = append(errs, "mem: "+err.Error())
	}
	if sm, err := mem.SwapMemory(); err == nil {
		u.SwapTotalBytes = pi(int64(sm.Total))
		u.SwapUsedBytes = pi(int64(sm.Used))
		u.SwapPercent = pf(sm.UsedPercent)
	}
	if io, err := disk.IOCounters(); err == nil {
		var r, w int64
		for _, c := range io {
			r += int64(c.ReadBytes)
			w += int64(c.WriteBytes)
		}
		u.DiskIOReadBytes, u.DiskIOWriteBytes = pi(r), pi(w)
	}
	if nio, err := net.IOCounters(false); err == nil && len(nio) > 0 {
		u.NetIOSentBytes = pi(int64(nio[0].BytesSent))
		u.NetIORecvBytes = pi(int64(nio[0].BytesRecv))
	}
	if len(errs) > 0 {
		u.Error = strings.Join(errs, "; ")
	}
	return u
}

// --- cgroup parsers (exported for tests) ---

func ParseCPUStat(content string) *int64 {
	for _, line := range strings.Split(content, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), " "); ok && k == "usage_usec" {
			if usec, err := strconv.ParseInt(v, 10, 64); err == nil {
				return pi(usec * 1000) // usec -> nsec
			}
		}
	}
	return nil
}

// ParseMemoryInt parses a single int; "max" (unlimited) -> nil.
func ParseMemoryInt(content string) *int64 {
	s := strings.TrimSpace(content)
	if s == "" || s == "max" {
		return nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return pi(n)
	}
	return nil
}

func ParseMemoryStat(content string) map[string]int64 {
	stats := map[string]int64{}
	for _, line := range strings.Split(content, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), " "); ok {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				stats[k] = n
			}
		}
	}
	return stats
}

// ParseIOStat sums rbytes/wbytes across all device lines (cgroup v2 io.stat).
func ParseIOStat(content string) (*int64, *int64) {
	if strings.TrimSpace(content) == "" {
		return nil, nil
	}
	var r, w int64
	for _, line := range strings.Split(content, "\n") {
		for _, tok := range strings.Fields(line) {
			k, v, ok := strings.Cut(tok, "=")
			if !ok {
				continue
			}
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				continue
			}
			switch k {
			case "rbytes":
				r += n
			case "wbytes":
				w += n
			}
		}
	}
	return pi(r), pi(w)
}

func ParseTasks(content string) *int64 {
	var n int64
	for _, line := range strings.Split(content, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			if _, err := strconv.Atoi(s); err == nil {
				n++
			}
		}
	}
	return pi(n)
}

// Analyze collects system + per-unit resource usage and computes top consumers.
func Analyze(_ context.Context, units []types.UnitHealthInfo) *types.ResourceAnalysisResult {
	res := &types.ResourceAnalysisResult{SystemUsage: SystemUsage()}

	names := make([]string, len(units))
	for i, u := range units {
		names[i] = u.Name
	}
	paths := systemd.ResolveCgroupPaths(names)

	for _, u := range units {
		rel, ok := paths[u.Name]
		if !ok {
			continue // no cgroup (sockets/targets/inactive) — skip, like Python's debug-skip
		}
		uu := types.UnitResourceUsage{Name: u.Name, CgroupPath: rel}
		if c, ok := systemd.ReadCgroupFile(rel, "cpu.stat"); ok {
			uu.CPUUsageNsec = ParseCPUStat(c)
		}
		if c, ok := systemd.ReadCgroupFile(rel, "memory.current"); ok {
			uu.MemoryCurrentByte = ParseMemoryInt(c)
		}
		if c, ok := systemd.ReadCgroupFile(rel, "memory.peak"); ok {
			uu.MemoryPeakBytes = ParseMemoryInt(c)
		}
		if c, ok := systemd.ReadCgroupFile(rel, "memory.max"); ok {
			uu.MemoryMaxBytes = ParseMemoryInt(c)
		}
		if c, ok := systemd.ReadCgroupFile(rel, "memory.high"); ok {
			uu.MemoryHighBytes = ParseMemoryInt(c)
		}
		if c, ok := systemd.ReadCgroupFile(rel, "memory.stat"); ok {
			stat := ParseMemoryStat(c)
			if v, ok := stat["anon"]; ok {
				uu.MemoryAnonBytes = pi(v)
			}
			if v, ok := stat["file"]; ok {
				uu.MemoryFileBytes = pi(v)
			}
		}
		if c, ok := systemd.ReadCgroupFile(rel, "io.stat"); ok {
			uu.IOReadBytes, uu.IOWriteBytes = ParseIOStat(c)
		}
		if c, ok := systemd.ReadCgroupFile(rel, "cgroup.procs"); ok {
			uu.TasksCurrent = ParseTasks(c)
		}
		res.UnitUsage = append(res.UnitUsage, uu)
	}

	res.TopMemoryUnits = topBy(res.UnitUsage, func(u types.UnitResourceUsage) int64 {
		return deref(u.MemoryCurrentByte)
	})
	res.TopCPUUnits = topBy(res.UnitUsage, func(u types.UnitResourceUsage) int64 {
		return deref(u.CPUUsageNsec)
	})
	res.TopIOUnits = topBy(res.UnitUsage, func(u types.UnitResourceUsage) int64 {
		return deref(u.IOReadBytes) + deref(u.IOWriteBytes)
	})
	return res
}

func deref(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func topBy(units []types.UnitResourceUsage, key func(types.UnitResourceUsage) int64) []types.UnitResourceUsage {
	out := make([]types.UnitResourceUsage, len(units))
	copy(out, units)
	sort.SliceStable(out, func(i, j int) bool { return key(out[i]) > key(out[j]) })
	if len(out) > topN {
		out = out[:topN]
	}
	return out
}
