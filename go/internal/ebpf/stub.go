//go:build !ebpf

package ebpf

import (
	"context"
	"errors"
	"time"

	"github.com/genie-tooling/sysdiag-analyzer-go/internal/types"
)

// Session is the no-eBPF stub. Start always errors so callers skip eBPF.
type Session struct{}

func Start(context.Context) (*Session, error) {
	return nil, errors.New("eBPF tracing not compiled into this build (rebuild with `make ebpf`)")
}

func (s *Session) Snapshot() *types.EBPFAnalysisResult {
	return &types.EBPFAnalysisResult{UnitsWithExecs: map[string]int{}, UnitsWithExits: map[string]int{}}
}

func (s *Session) Close() {}

// Run is the no-eBPF stub used by the default build.
func Run(_ context.Context, _ time.Duration) *types.EBPFAnalysisResult {
	return &types.EBPFAnalysisResult{
		UnitsWithExecs: map[string]int{},
		UnitsWithExits: map[string]int{},
		Error: "eBPF tracing not compiled into this build. Rebuild with `make ebpf` " +
			"(uses committed bindings; runtime needs root + a BTF-capable kernel).",
	}
}
