// Package resources collects system-wide (gopsutil) and per-unit cgroup v2
// resource usage, mirroring modules/resources.py.
package resources

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/systemd"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

const (
	topN            = 10
	childMinMemMB   = 5.0  // CHILD_PROCESS_MIN_MEM_MB
	childMinCPUSecs = 60.0 // CHILD_PROCESS_MIN_CPU_SECONDS
)

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
	u.HugepagesBytes, u.HugepagesFreeBytes = meminfoHugepages()
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

	// Child-process scan (one /proc walk) runs concurrently with the per-unit
	// cgroup reads, which are themselves parallelized (bounded) since they're
	// independent file reads.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); res.ChildProcessGroups = scanChildGroups(units) }()

	type job struct{ name, rel string }
	var jobs []job
	for _, u := range units {
		if rel, ok := paths[u.Name]; ok {
			jobs = append(jobs, job{u.Name, rel})
		}
	}
	out := make([]types.UnitResourceUsage, len(jobs))
	sem := make(chan struct{}, 16)
	var rwg sync.WaitGroup
	for i, j := range jobs {
		rwg.Add(1)
		sem <- struct{}{}
		go func(i int, j job) {
			defer rwg.Done()
			defer func() { <-sem }()
			out[i] = readUnitUsage(j.name, j.rel)
		}(i, j)
	}
	rwg.Wait()
	res.UnitUsage = out
	wg.Wait()

	// Rank actual consumers, not the slice nesting chain that repeats the same
	// usage up the cgroup tree (full UnitUsage is kept intact for JSON).
	leaves := types.CollapseHierarchy(res.UnitUsage)
	res.TopMemoryUnits = topBy(leaves, func(u types.UnitResourceUsage) int64 {
		return deref(u.MemoryCurrentByte)
	})
	res.TopCPUUnits = topBy(leaves, func(u types.UnitResourceUsage) int64 {
		return deref(u.CPUUsageNsec)
	})
	res.TopIOUnits = topBy(leaves, func(u types.UnitResourceUsage) int64 {
		return deref(u.IOReadBytes) + deref(u.IOWriteBytes)
	})
	return res
}

// UnitProcesses returns per-PID resource usage for the processes directly in a
// unit's cgroup (forensic drill-down for analyze-unit), sorted by RSS desc.
func UnitProcesses(rel string) []types.ProcessUsage {
	c, ok := systemd.ReadCgroupFile(rel, "cgroup.procs")
	if !ok {
		return nil
	}
	var out []types.ProcessUsage
	for _, f := range strings.Fields(c) {
		if pid, err := strconv.Atoi(f); err == nil {
			out = append(out, readProcess(pid))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return deref(out[i].RSSBytes) > deref(out[j].RSSBytes) })
	return out
}

func readProcess(pid int) types.ProcessUsage {
	pu := types.ProcessUsage{Pid: pid}
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return pu
	}
	if n, err := p.Name(); err == nil {
		pu.Comm = n
	}
	if mi, err := p.MemoryInfo(); err == nil && mi != nil {
		r, s := int64(mi.RSS), int64(mi.Swap)
		pu.RSSBytes, pu.SwapBytes = &r, &s
	}
	if t, err := p.Times(); err == nil && t != nil {
		c := t.User + t.System
		pu.CPUSeconds = &c
	}
	if io, err := p.IOCounters(); err == nil && io != nil {
		rb, wb := int64(io.ReadBytes), int64(io.WriteBytes)
		pu.IOReadBytes, pu.IOWriteBytes = &rb, &wb
	}
	pu.DirtyBytes = procDirty(pid)
	return pu
}

// procDirty sums Private_Dirty + Shared_Dirty from /proc/<pid>/smaps_rollup (kB→bytes).
func procDirty(pid int) *int64 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/smaps_rollup", pid))
	if err != nil {
		return nil
	}
	var total int64
	found := false
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Private_Dirty:") || strings.HasPrefix(line, "Shared_Dirty:") {
			if fields := strings.Fields(line); len(fields) >= 2 {
				if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					total += kb * 1024
					found = true
				}
			}
		}
	}
	if !found {
		return nil
	}
	return &total
}

// readUnitUsage reads all cgroup v2 metric files for one unit.
func readUnitUsage(name, rel string) types.UnitResourceUsage {
	uu := types.UnitResourceUsage{Name: name, CgroupPath: rel}
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
		if v, ok := stat["pgmajfault"]; ok {
			uu.MemoryPgMajfault = pi(v)
		}
		if v, ok := stat["pagetables"]; ok {
			uu.MemoryPagetables = pi(v)
		}
		if v, ok := stat["hugetlb"]; ok {
			uu.MemoryHugetlb = pi(v)
		}
	}
	if c, ok := systemd.ReadCgroupFile(rel, "io.stat"); ok {
		uu.IOReadBytes, uu.IOWriteBytes = ParseIOStat(c)
	}
	if c, ok := systemd.ReadCgroupFile(rel, "cgroup.procs"); ok {
		uu.TasksCurrent = ParseTasks(c)
	}
	if c, ok := systemd.ReadCgroupFile(rel, "cpu.pressure"); ok {
		uu.PSICPUPressure = ParsePressure(c)
	}
	if c, ok := systemd.ReadCgroupFile(rel, "memory.pressure"); ok {
		uu.PSIMemPressure = ParsePressure(c)
	}
	if c, ok := systemd.ReadCgroupFile(rel, "io.pressure"); ok {
		uu.PSIIOPressure = ParsePressure(c)
	}
	return uu
}

// meminfoHugepages reads the hugepage pool from /proc/meminfo. Hugetlb is the
// total bytes pinned in hugepages — guest RAM of hugepage-backed VMs lives here
// and is invisible to cgroup memory.current. nil when no hugepages are reserved.
func meminfoHugepages() (total, free *int64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil, nil
	}
	var hugetlbKB, freePages, sizeKB int64
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch strings.TrimSuffix(f[0], ":") {
		case "Hugetlb":
			hugetlbKB, _ = strconv.ParseInt(f[1], 10, 64)
		case "HugePages_Free":
			freePages, _ = strconv.ParseInt(f[1], 10, 64)
		case "Hugepagesize":
			sizeKB, _ = strconv.ParseInt(f[1], 10, 64)
		}
	}
	if hugetlbKB <= 0 {
		return nil, nil
	}
	t := hugetlbKB * 1024
	fr := freePages * sizeKB * 1024
	return &t, &fr
}

// ParsePressure extracts the "some avg10" stall percentage (0..100) from a
// cgroup {cpu,memory,io}.pressure file; nil if PSI is unavailable.
func ParsePressure(content string) *float64 {
	for _, line := range strings.Split(content, "\n") {
		if !strings.HasPrefix(line, "some ") {
			continue
		}
		for _, f := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(f, "avg10="); ok {
				if p, err := strconv.ParseFloat(v, 64); err == nil {
					return &p
				}
			}
		}
	}
	return nil
}

// CollectUnitUsage is the fast per-unit read path for the live `top` view: it
// resolves missing cgroup paths once into cache (negative results cached as "")
// and re-reads only the cheap /sys files. No child-process scan.
func CollectUnitUsage(units []types.UnitHealthInfo, cache map[string]string) []types.UnitResourceUsage {
	var missing []string
	for _, u := range units {
		if _, ok := cache[u.Name]; !ok {
			missing = append(missing, u.Name)
		}
	}
	if len(missing) > 0 {
		resolved := systemd.ResolveCgroupPaths(missing)
		for _, name := range missing {
			cache[name] = resolved[name] // "" if no cgroup (cached negative)
		}
	}
	var out []types.UnitResourceUsage
	for _, u := range units {
		if rel := cache[u.Name]; rel != "" {
			out = append(out, readUnitUsage(u.Name, rel))
		}
	}
	return out
}

func deref(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// scanChildGroups aggregates non-systemd-managed descendant processes of each
// service's MainPID by command name (e.g. containers under docker.service),
// linking them back to the parent unit. Mirrors _scan_and_group_child_processes.
func scanChildGroups(units []types.UnitHealthInfo) []types.ChildProcessGroupUsage {
	var services []string
	for _, u := range units {
		if strings.HasSuffix(u.Name, ".service") {
			services = append(services, u.Name)
		}
	}
	props := systemd.ShowProperties(services, []string{"MainPID"})

	// Read /proc ONCE into a pid table + ppid->children adjacency, then walk each
	// service's tree in memory. (gopsutil's Children() re-scans all of /proc per
	// node, which was O(services x procs) and dominated `run`'s wall-clock.)
	infos, children := processTable()

	type acc struct {
		unit, cmd string
		pids      []int
		mem       int64
		cpu       float64
	}
	groups := map[string]*acc{}
	for unit, kv := range props {
		pid, err := strconv.Atoi(kv["MainPID"])
		if err != nil || pid <= 0 {
			continue
		}
		for _, cpid := range descendantPids(int32(pid), children) {
			info := infos[cpid]
			if info == nil || info.comm == "" {
				continue
			}
			key := unit + "\x00" + info.comm
			a := groups[key]
			if a == nil {
				a = &acc{unit: unit, cmd: info.comm}
				groups[key] = a
			}
			a.pids = append(a.pids, int(cpid))
			a.mem += info.rss
			a.cpu += info.cpu
		}
	}

	var out []types.ChildProcessGroupUsage
	for _, a := range groups {
		if float64(a.mem)/(1024*1024) < childMinMemMB && a.cpu < childMinCPUSecs {
			continue
		}
		mem, cpu := a.mem, a.cpu
		out = append(out, types.ChildProcessGroupUsage{
			CommandName: a.cmd, ParentUnit: a.unit, ProcessCount: len(a.pids),
			Pids: a.pids, AggregatedMemoryBytes: &mem, AggregatedCPUSecondsTot: &cpu,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		ci, cj := derefF(out[i].AggregatedCPUSecondsTot), derefF(out[j].AggregatedCPUSecondsTot)
		if ci != cj {
			return ci > cj
		}
		return deref(out[i].AggregatedMemoryBytes) > deref(out[j].AggregatedMemoryBytes)
	})
	return out
}

func derefF(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

// CgroupFDCount sums open file descriptors across a cgroup's direct processes
// (best-effort; processes we can't inspect are skipped). nil if none readable.
func CgroupFDCount(rel string) *int {
	c, ok := systemd.ReadCgroupFile(rel, "cgroup.procs")
	if !ok {
		return nil
	}
	total, seen := 0, false
	for _, line := range strings.Split(c, "\n") {
		pid, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			continue
		}
		p, err := process.NewProcess(int32(pid))
		if err != nil {
			continue
		}
		if n, err := p.NumFDs(); err == nil {
			total += int(n)
			seen = true
		}
	}
	if !seen {
		return nil
	}
	return &total
}

// descendants returns all recursive child processes of pid (excluding pid itself).
type pinfo struct {
	ppid int32
	comm string
	rss  int64
	cpu  float64
}

// processTable reads every process once, returning per-PID info and a
// ppid->children adjacency map. One /proc walk total (vs gopsutil Children()'s
// per-node rescan).
func processTable() (map[int32]*pinfo, map[int32][]int32) {
	procs, err := process.Processes()
	if err != nil {
		return map[int32]*pinfo{}, map[int32][]int32{}
	}
	// Gather each process's fields concurrently (gopsutil does several /proc
	// reads per process; doing them serially over hundreds of PIDs dominated).
	type rec struct {
		pid int32
		pi  *pinfo
	}
	recs := make([]rec, len(procs))
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for i, p := range procs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p *process.Process) {
			defer wg.Done()
			defer func() { <-sem }()
			pi := &pinfo{}
			pi.ppid, _ = p.Ppid()
			pi.comm, _ = p.Name()
			if mi, err := p.MemoryInfo(); err == nil && mi != nil {
				pi.rss = int64(mi.RSS)
			}
			if t, err := p.Times(); err == nil && t != nil {
				pi.cpu = t.User + t.System
			}
			recs[i] = rec{p.Pid, pi}
		}(i, p)
	}
	wg.Wait()

	infos := make(map[int32]*pinfo, len(recs))
	children := make(map[int32][]int32, len(recs))
	for _, r := range recs {
		if r.pi == nil {
			continue
		}
		infos[r.pid] = r.pi
		children[r.pi.ppid] = append(children[r.pi.ppid], r.pid)
	}
	return infos, children
}

// descendantPids returns all PIDs below root (exclusive) via the adjacency map.
func descendantPids(root int32, children map[int32][]int32) []int32 {
	var out []int32
	seen := map[int32]bool{}
	queue := append([]int32(nil), children[root]...)
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
		queue = append(queue, children[p]...)
	}
	return out
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
