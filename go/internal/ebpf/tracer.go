//go:build ebpf

package ebpf

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

var unitSuffixes = []string{
	".service", ".scope", ".socket", ".target", ".mount", ".swap", ".slice", ".timer", ".path",
}

// Run loads the eBPF programs, lets the kernel aggregate per-cgroup process
// stats for dur, then reads the maps and attributes them to systemd units.
func Run(ctx context.Context, dur time.Duration) *types.EBPFAnalysisResult {
	res := &types.EBPFAnalysisResult{UnitsWithExecs: map[string]int{}, UnitsWithExits: map[string]int{}}

	// Kernels >= 5.11 use memcg accounting; ignore failure (needs CAP_SYS_RESOURCE).
	_ = rlimit.RemoveMemlock()

	var objs tracerObjects
	if err := loadTracerObjects(&objs, nil); err != nil {
		res.Error = "loading eBPF objects (needs root and a BTF-capable kernel): " + err.Error()
		return res
	}
	defer objs.Close()

	// exec/exit are essential; oom/signal use kfuncs and may be unavailable on
	// some kernels — tolerate their attach failure (those columns stay zero).
	attach := []struct {
		group, name string
		prog        *ebpf.Program
		essential   bool
	}{
		{"syscalls", "sys_enter_execve", objs.HandleExecve, true},
		{"sched", "sched_process_exit", objs.HandleExit, true},
		{"sched", "sched_switch", objs.HandleSchedSwitch, false},
		{"oom", "mark_victim", objs.HandleOom, false},
		{"signal", "signal_generate", objs.HandleSignal, false},
	}
	for _, a := range attach {
		lnk, err := link.Tracepoint(a.group, a.name, a.prog, nil)
		if err != nil {
			if a.essential {
				res.Error = fmt.Sprintf("attaching %s/%s: %v", a.group, a.name, err)
				return res
			}
			continue // optional probe unavailable on this kernel
		}
		defer lnk.Close()
	}

	// Aggregate over the window.
	select {
	case <-ctx.Done():
	case <-time.After(dur):
	}

	inode := buildCgroupInodeMap("/sys/fs/cgroup")
	resolve := func(cgid uint64) string {
		if u := inode[cgid]; u != "" {
			return u
		}
		return fmt.Sprintf("cgroup:%d", cgid)
	}

	agg := map[string]*types.EBPFUnitStat{}
	get := func(unit string) *types.EBPFUnitStat {
		if s := agg[unit]; s != nil {
			return s
		}
		s := &types.EBPFUnitStat{Unit: unit}
		agg[unit] = s
		return s
	}

	var key uint64
	var val tracerProcStat
	it := objs.Stats.Iterate()
	for it.Next(&key, &val) {
		u := get(resolve(key))
		u.Execs += val.Execs
		u.Exits += val.Exits
		u.ExitNonzero += val.ExitNonzero
		u.ExitSignaled += val.ExitSignaled
		u.OOMKills += val.OomKills
		u.SigKillRcvd += val.SigkillRcvd
		u.SigTermRcvd += val.SigtermRcvd
		u.OffCPUNs += val.OffcpuNs
		if val.LastSignal != 0 {
			u.LastSignal = val.LastSignal
		}
		if val.LastExitCode != 0 {
			u.LastExitCode = val.LastExitCode
		}
	}

	// Most-executed binary per unit.
	best := map[string]uint64{}
	var ek tracerExecKey
	var ev uint64
	it2 := objs.ExecNames.Iterate()
	for it2.Next(&ek, &ev) {
		unit := resolve(ek.Cgid)
		if ev > best[unit] {
			best[unit] = ev
			u := get(unit)
			u.TopCommand = i8str(ek.Comm[:])
			u.TopCommandHits = ev
		}
	}

	for unit, s := range agg {
		if s.Execs > 0 {
			res.UnitsWithExecs[unit] = int(s.Execs)
		}
		if s.Exits > 0 {
			res.UnitsWithExits[unit] = int(s.Exits)
		}
		// Drop trivial entries created only by a sub-millisecond D-state wake.
		meaningful := s.Execs > 0 || s.Exits > 0 || s.ExitNonzero > 0 || s.ExitSignaled > 0 ||
			s.OOMKills > 0 || s.SigKillRcvd > 0 || s.SigTermRcvd > 0 || s.OffCPUNs >= 1_000_000
		if meaningful {
			res.UnitStats = append(res.UnitStats, *s)
		}
	}
	sort.Slice(res.UnitStats, func(i, j int) bool {
		a, b := res.UnitStats[i], res.UnitStats[j]
		fa := a.OOMKills + a.ExitSignaled + a.ExitNonzero + a.SigKillRcvd
		fb := b.OOMKills + b.ExitSignaled + b.ExitNonzero + b.SigKillRcvd
		if fa != fb {
			return fa > fb // units with failures first
		}
		if a.Execs != b.Execs {
			return a.Execs > b.Execs
		}
		return a.Unit < b.Unit
	})
	return res
}

// i8str turns a NUL-terminated C char array (as []int8) into a Go string.
func i8str(b []int8) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}

// buildCgroupInodeMap maps cgroup directory inode -> owning systemd unit, so the
// kernel cgroup id from each map entry can be resolved to a unit name.
func buildCgroupInodeMap(base string) map[uint64]string {
	m := map[uint64]string{}
	_ = filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		if unit := deriveUnit(path, base); unit != "" {
			m[st.Ino] = unit
		}
		return nil
	})
	return m
}

func deriveUnit(path, base string) string {
	rel := strings.TrimPrefix(strings.TrimPrefix(path, base), "/")
	parts := strings.Split(rel, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		for _, suf := range unitSuffixes {
			if strings.HasSuffix(parts[i], suf) {
				return parts[i]
			}
		}
	}
	return ""
}
