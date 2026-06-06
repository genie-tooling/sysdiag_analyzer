// Package systemd lists units (native D-Bus, systemctl fallback), reads unit
// properties in one batched systemctl call, and reads cgroup v2 files.
package systemd

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	godbus "github.com/coreos/go-systemd/v22/dbus"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

const CgroupBase = "/sys/fs/cgroup"

// UnitLogs returns up to the last n journal lines for a unit (oldest→newest),
// via journalctl. Mirrors health.py's _get_unit_logs.
func UnitLogs(unit string, n int) []string {
	if n <= 0 {
		n = 20
	}
	out, err := exec.Command("journalctl", "-u", unit, "-n", strconv.Itoa(n),
		"--no-pager", "--output=short-iso").Output()
	if err != nil {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if l == "" || strings.HasPrefix(l, "-- ") { // skip "-- No entries --"/boot markers
			continue
		}
		lines = append(lines, l)
	}
	return lines
}

// ListUnits returns currently-loaded units via the systemd D-Bus API, falling
// back to `systemctl list-units --output=json` if D-Bus is unavailable.
func ListUnits(ctx context.Context) ([]types.UnitHealthInfo, error) {
	if conn, err := godbus.NewSystemdConnectionContext(ctx); err == nil {
		defer conn.Close()
		if us, err := conn.ListUnitsContext(ctx); err == nil {
			out := make([]types.UnitHealthInfo, 0, len(us))
			for _, u := range us {
				out = append(out, types.UnitHealthInfo{
					Name: u.Name, LoadState: u.LoadState, ActiveState: u.ActiveState,
					SubState: u.SubState, Description: u.Description, Path: string(u.Path),
				})
			}
			return out, nil
		}
	}
	return listUnitsJSON()
}

func listUnitsJSON() ([]types.UnitHealthInfo, error) {
	out, err := exec.Command("systemctl", "list-units", "--all", "--output=json", "--no-pager").Output()
	if err != nil {
		return nil, err
	}
	var raw []map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}
	units := make([]types.UnitHealthInfo, 0, len(raw))
	for _, r := range raw {
		name, _ := r["unit"].(string)
		if name == "" {
			continue
		}
		s := func(k string) string { v, _ := r[k].(string); return v }
		units = append(units, types.UnitHealthInfo{
			Name: name, LoadState: s("load"), ActiveState: s("active"),
			SubState: s("sub"), Description: s("description"),
		})
	}
	return units, nil
}

// ShowProperties runs one batched `systemctl show -p Id -p <props...>` and maps
// each unit (by Id) to its property values. Mirrors the Python systemctl batch.
func ShowProperties(units, props []string) map[string]map[string]string {
	result := map[string]map[string]string{}
	if len(units) == 0 {
		return result
	}
	args := []string{"show", "--property=Id"}
	for _, p := range props {
		args = append(args, "--property="+p)
	}
	args = append(args, "--")
	args = append(args, units...)
	out, err := exec.Command("systemctl", args...).Output()
	if err != nil {
		return result
	}
	for _, record := range strings.Split(string(out), "\n\n") {
		var id string
		kv := map[string]string{}
		for _, line := range strings.Split(record, "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			if k == "Id" {
				id = v
			} else {
				kv[k] = v
			}
		}
		if id != "" {
			result[id] = kv
		}
	}
	return result
}

var cgroupUnitSuffixes = []string{
	".service", ".scope", ".socket", ".target", ".mount", ".swap", ".slice", ".timer", ".path",
}

// CgroupPathsFS walks /sys/fs/cgroup once and maps each unit name to its
// relative cgroup path. systemd only keeps a cgroup directory for *active*
// units, so this is both complete and far cheaper than `systemctl show
// ControlGroup` over every unit (a filesystem walk vs. a per-unit manager query).
func CgroupPathsFS() map[string]string {
	out := map[string]string{}
	_ = filepath.WalkDir(CgroupBase, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		name := d.Name()
		for _, suf := range cgroupUnitSuffixes {
			if strings.HasSuffix(name, suf) {
				out[name] = strings.TrimPrefix(strings.TrimPrefix(path, CgroupBase), "/")
				break
			}
		}
		return nil
	})
	return out
}

// ResolveCgroupPaths returns relative cgroup paths (leading slash stripped) for
// the given units; absent if the unit has no cgroup (e.g. inactive).
func ResolveCgroupPaths(units []string) map[string]string {
	all := CgroupPathsFS()
	paths := make(map[string]string, len(units))
	for _, u := range units {
		if rel, ok := all[u]; ok {
			paths[u] = rel
		}
	}
	return paths
}

// ReadCgroupFile reads a file under a unit's cgroup directory.
func ReadCgroupFile(relCgroup, name string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(CgroupBase, relCgroup, name))
	if err != nil {
		return "", false
	}
	return string(b), true
}

// Hostname returns the kernel hostname.
func Hostname() string {
	h, _ := os.Hostname()
	return h
}

// BootID reads the current boot id from /proc.
func BootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
