# sysdiag-analyzer (Go)

A from-scratch Go port of the Python `sysdiag_analyzer` — a **single, statically
linked, CGo-free binary** for systemd/system-health diagnostics. Every feature is
compiled in; the only thing dropped from the default build is the LSTM/TensorFlow
deep mode (the statistical detector is the default and covers out-of-the-box use).

## Why the port
- **No runtime toolchain for eBPF** — the BPF program is compiled once at build
  time (clang/`bpf2go`, CO-RE) and embedded; the runtime needs only a BTF-capable
  kernel (no clang/kernel headers per host, unlike Python+BCC).
- **No compiled system-lib deps** — native D-Bus (`go-systemd`, pure Go), `/proc`
  via `gopsutil`, cgroup-path fallback via `systemctl`. No `dbus-python`/`libsystemd`
  build. journald is read by shelling `journalctl` (keeps the binary fully static).
- **Lighter CPU** — one static binary, native D-Bus instead of per-call subprocess,
  no interpreter, no TensorFlow.

Reports use the **same JSON schema** and the exporter the **same metric names** as
the Python tool, so history and dashboards interoperate.

## Build
```bash
CGO_ENABLED=0 go build -o sysdiag-analyzer ./cmd/sysdiag-analyzer   # static, ~15 MB
ldd ./sysdiag-analyzer    # -> "not a dynamic executable"
go test ./...
```
Requires Go 1.24+. Run as **root** for full per-unit / journal data (system-wide
stats work unprivileged).

### Optional: eBPF process tracing (`--enable-ebpf`)
The default binary ships an eBPF stub. To enable real tracing you compile the
CO-RE object once (build-time `clang` + `bpftool`; runtime needs only BTF):
```bash
sudo apt install -y clang llvm libbpf-dev linux-tools-common   # or distro equivalent
go generate ./...                 # bpftool -> vmlinux.h ; bpf2go -> tracer_bpf*.go
go build -tags ebpf -o sysdiag-analyzer ./cmd/sysdiag-analyzer
```

## Commands
`run` (flags: `--enable-ebpf`, `--analyze-ml`, `--analyze-llm`, `--analyze-full-graph`,
`--since`, `--no-save`, `--output rich|json`), `top` (`--sort mem|cpu|io|limit`,
`--interval`, `--count`), `exporter` (`--host/--port/-i`), `analyze-{health,resources,boot,logs}`,
`show-history`, `config show`.

## Anomaly detection (`--analyze-ml`)
Selected by `[models].method`:
- **`statistical`** (default) — stateless. For each unit/metric it computes a robust
  modified z-score (median + MAD) over the recent history window; needs no prior state
  but only sees what is on disk.
- **`baseline`** — online & adaptive. Learns each unit/metric baseline as an EWMA
  control chart (mean + variance, West's algorithm) and flags samples beyond
  `mean + k·σ`. Counters (cpu/io) are scored as per-second rates with reset detection;
  gauges (mem/tasks) as levels. State persists in `<models.directory>/baseline.json`,
  warms up silently for `min_updates` (default 8) samples, tolerates steady drift, and
  prunes units unseen for 7 days. Optional `seasonal = true` keeps a separate baseline
  per hour-of-day. Tunables: `ewma_alpha` (0.3), `min_updates` (8), `seasonal` (false),
  `sensitivity` (low/medium/high → k = 4.0/3.0/2.5).
- **`lstm`** — not in the default build; falls back to `statistical` with a recorded
  warning (see *Not ported*).

## Layout
```
cmd/sysdiag-analyzer   CLI (cobra)
internal/types         report data model (JSON tags match the Python schema)
internal/config        TOML config ([llm]/[history]/[models])
internal/systemd       D-Bus unit list + batched systemctl props + cgroup reads
internal/collect/*     boot, health, resources (+child groups, fd), logs, deps
internal/analyze/*     stats (modified-z), baseline (online EWMA control chart), leak (anon slope), llm
internal/features      report -> per-unit feature rows
internal/history       gzipped-JSON persistence + retention
internal/exporter      prometheus/client_golang collector
internal/tui           bubbletea live `top`
internal/ebpf          cilium/ebpf loader (-tags ebpf) + stub
bpf/tracer.c           CO-RE exec/exit tracepoints
```

## Not ported
- **LSTM/TensorFlow** deep anomaly mode (`retrain-ml`, `[models].method = "lstm"`).
  See the bonus plan for adding it back in Go (gorgonia) behind a `-tags lstm` build.
