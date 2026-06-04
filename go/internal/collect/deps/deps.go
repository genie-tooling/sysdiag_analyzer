// Package deps analyzes dependencies of failed units and detects dependency
// cycles in the full graph, mirroring modules/dependencies.py.
package deps

import (
	"os/exec"
	"strings"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/systemd"
	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

var treeTrim = "●○├└│─ \t"

// AnalyzeFailed inspects each failed unit's dependencies and flags problematic ones.
func AnalyzeFailed(failed []types.UnitHealthInfo, states map[string]types.UnitHealthInfo) *types.DependencyAnalysisResult {
	res := &types.DependencyAnalysisResult{FailedUnitDependencies: []types.FailedUnitDependencyInfo{}}
	for _, fu := range failed {
		info := types.FailedUnitDependencyInfo{UnitName: fu.Name, Dependencies: []types.DependencyInfo{}}
		out, err := exec.Command("systemctl", "list-dependencies", fu.Name, "--plain", "--no-pager").Output()
		if err != nil {
			info.Error = "list-dependencies failed: " + err.Error()
			res.FailedUnitDependencies = append(res.FailedUnitDependencies, info)
			continue
		}
		seen := map[string]bool{fu.Name: true}
		for _, line := range strings.Split(string(out), "\n") {
			name := strings.Trim(line, treeTrim)
			if name == "" || !strings.Contains(name, ".") || seen[name] {
				continue
			}
			seen[name] = true
			d := types.DependencyInfo{Name: name, Type: "Requires"} // type not exposed by list-dependencies
			if st, ok := states[name]; ok {
				d.CurrentLoadState = st.LoadState
				d.CurrentActiveState = st.ActiveState
				d.CurrentSubState = st.SubState
				d.IsProblematic = st.ActiveState == "failed" || st.LoadState == "not-found"
			} else {
				d.IsProblematic = true // unknown / not loaded
				d.CurrentLoadState = "not-found"
			}
			info.Dependencies = append(info.Dependencies, d)
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
