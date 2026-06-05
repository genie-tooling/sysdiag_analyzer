// Package deps analyzes dependencies of failed units and detects dependency
// cycles in the full graph, mirroring modules/dependencies.py.
package deps

import (
	"sort"
	"strings"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/systemd"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

// Dependency relation properties fetched per unit (order = precedence; first wins).
var depPropKeys = []string{
	"Requires", "Requisite", "Wants", "BindsTo", "Before", "After", "PartOf", "ConsistsOf",
}

// RelationProps returns the dependency relation property names to fetch for a
// unit (so callers can include them in a single systemctl show).
func RelationProps() []string { return append([]string(nil), depPropKeys...) }

// strongDepTypes mirror Python: their failure/absence can cause the unit to fail.
var strongDepTypes = map[string]bool{
	"Requires": true, "ConsistsOf": true, "BindsTo": true,
	"Requisite": true, "PartOf": true, "Unknown": true,
}

// isDepProblematic ports modules/dependencies.py:_is_dependency_problematic.
func isDepProblematic(depType, load, active, sub string) bool {
	if strongDepTypes[depType] {
		return active == "failed" || active == "inactive" || sub == "dead" ||
			load == "not-found" || load == ""
	}
	if depType == "Wants" { // weaker: only an outright failure counts
		return active == "failed"
	}
	return false // Before/After are ordering-only
}

// depMapFromProps extracts dep name -> relation type from a unit's properties.
func depMapFromProps(kv map[string]string) map[string]string {
	m := map[string]string{}
	for _, key := range depPropKeys {
		for _, name := range strings.Fields(kv[key]) {
			if name != "" {
				if _, exists := m[name]; !exists {
					m[name] = key
				}
			}
		}
	}
	return m
}

// resolveStates returns load/active/sub for each dep, using the known unit map
// where possible and a single batched `systemctl show` for the rest.
func resolveStates(names []string, known map[string]types.UnitHealthInfo) map[string]types.UnitHealthInfo {
	out := map[string]types.UnitHealthInfo{}
	var missing []string
	for _, n := range names {
		if st, ok := known[n]; ok {
			out[n] = st
		} else {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		props := systemd.ShowProperties(missing, []string{"LoadState", "ActiveState", "SubState"})
		for n, kv := range props {
			out[n] = types.UnitHealthInfo{Name: n, LoadState: kv["LoadState"], ActiveState: kv["ActiveState"], SubState: kv["SubState"]}
		}
	}
	return out
}

// buildDeps turns a dep map into sorted, state-resolved, problem-flagged DependencyInfos.
func buildDeps(depMap map[string]string, known map[string]types.UnitHealthInfo) []types.DependencyInfo {
	names := make([]string, 0, len(depMap))
	for n := range depMap {
		names = append(names, n)
	}
	sort.Strings(names)
	depStates := resolveStates(names, known)
	out := make([]types.DependencyInfo, 0, len(names))
	for _, name := range names {
		typ := depMap[name]
		d := types.DependencyInfo{Name: name, Type: typ}
		if st, ok := depStates[name]; ok {
			d.CurrentLoadState, d.CurrentActiveState, d.CurrentSubState = st.LoadState, st.ActiveState, st.SubState
		}
		if d.CurrentLoadState == "" {
			d.CurrentLoadState = "not-found"
		}
		d.IsProblematic = isDepProblematic(typ, d.CurrentLoadState, d.CurrentActiveState, d.CurrentSubState)
		out = append(out, d)
	}
	return out
}

// AnalyzeUnit returns the dependency breakdown for a single unit (any state),
// given that unit's already-fetched properties. Mirrors unit_analyzer.py.
func AnalyzeUnit(unitName string, unitProps map[string]string, known map[string]types.UnitHealthInfo) *types.FailedUnitDependencyInfo {
	return &types.FailedUnitDependencyInfo{
		UnitName:     unitName,
		Dependencies: buildDeps(depMapFromProps(unitProps), known),
	}
}

// AnalyzeFailed inspects each failed unit's dependencies and flags problematic ones,
// preserving the real relation type (Requires/Wants/After/...) per Python.
func AnalyzeFailed(failed []types.UnitHealthInfo, states map[string]types.UnitHealthInfo) *types.DependencyAnalysisResult {
	res := &types.DependencyAnalysisResult{FailedUnitDependencies: []types.FailedUnitDependencyInfo{}}
	names := make([]string, len(failed))
	for i, fu := range failed {
		names[i] = fu.Name
	}
	props := systemd.ShowProperties(names, depPropKeys)
	for _, fu := range failed {
		info := types.FailedUnitDependencyInfo{UnitName: fu.Name, Dependencies: []types.DependencyInfo{}}
		if kv, ok := props[fu.Name]; ok {
			info.Dependencies = buildDeps(depMapFromProps(kv), states)
		} else {
			info.Error = "could not fetch dependency properties via systemctl show"
		}
		res.FailedUnitDependencies = append(res.FailedUnitDependencies, info)
	}
	return res
}

// AnalyzeFullGraph builds the Requires/Wants graph and reports any cycles.
func AnalyzeFullGraph(unitNames []string) *types.FullDependencyAnalysisResult {
	res := &types.FullDependencyAnalysisResult{DetectedCycles: [][]string{}}
	props := systemd.ShowProperties(unitNames, []string{"Requires", "Wants"})
	if len(props) == 0 {
		res.DependencyFetchError = "could not fetch unit dependencies via systemctl show"
		return res
	}
	graph := map[string][]string{}
	for unit, kv := range props {
		var edges []string
		edges = append(edges, strings.Fields(kv["Requires"])...)
		edges = append(edges, strings.Fields(kv["Wants"])...)
		graph[unit] = edges
	}
	res.DetectedCycles = findCycles(graph)
	return res
}

// findCycles returns simple cycles via DFS (white/gray/black colouring).
func findCycles(graph map[string][]string) [][]string {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	var stack []string
	var cycles [][]string
	seenCycle := map[string]bool{}

	var dfs func(node string)
	dfs = func(node string) {
		color[node] = gray
		stack = append(stack, node)
		for _, next := range graph[node] {
			switch color[next] {
			case gray:
				// Back-edge: extract the cycle from the stack.
				for i := len(stack) - 1; i >= 0; i-- {
					if stack[i] == next {
						cyc := append([]string(nil), stack[i:]...)
						key := strings.Join(cyc, "->")
						if !seenCycle[key] && len(cycles) < 100 {
							seenCycle[key] = true
							cycles = append(cycles, cyc)
						}
						break
					}
				}
			case white:
				if _, exists := graph[next]; exists {
					dfs(next)
				}
			}
		}
		stack = stack[:len(stack)-1]
		color[node] = black
	}

	for node := range graph {
		if color[node] == white {
			dfs(node)
		}
	}
	return cycles
}
