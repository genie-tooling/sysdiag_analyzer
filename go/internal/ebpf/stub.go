//go:build !ebpf

package ebpf

import (
	"context"
	"time"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

// Run is the no-eBPF stub used by the default build.
func Run(_ context.Context, _ time.Duration) *types.EBPFAnalysisResult {
	return &types.EBPFAnalysisResult{
		UnitsWithExecs: map[string]int{},
		UnitsWithExits: map[string]int{},
		Error: "eBPF tracing not compiled into this build. Rebuild with `make ebpf` " +
			"(uses committed bindings; runtime needs root + a BTF-capable kernel).",
	}
}
