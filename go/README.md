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

## Requirements

**Runtime** (the host you run it on):
- **Linux with systemd on cgroup v2.** `systemctl`, `journalctl`, and `systemd-analyze`
  must be on `PATH` (used for unit lists, boot timing, logs, dependencies).
- **Privileges:** system-wide stats work unprivileged; run as **root** for full per-unit
  cgroup metrics, failed-unit journal logs, and dependency analysis. `--enable-ebpf`
  **requires root** (or `CAP_BPF`+`CAP_PERFMON`).
- **eBPF (`--enable-ebpf`):** a **BTF-capable kernel** (`/sys/kernel/btf/vmlinux` present;
  kernel ≥ 5.8, ≥ 5.11 recommended). No clang/headers needed at runtime.
- **LLM (`--analyze-llm`):** one of — a running **Ollama**, an **OpenAI-compatible**
  endpoint, or the **`claude` CLI** on `PATH` (provider `claude-code`, uses your existing
  Claude Code login; no API key).

**Build** (the host you compile on):
- **Default binary:** **Go 1.24+** only — `CGO_ENABLED=0`, no system `-dev` libraries.
- **eBPF binary (`make ebpf`):** also just Go — the bpf2go bindings
  (`internal/ebpf/tracer_bpf*.{go,o}`) are **committed**, so no clang/bpftool needed.
- **Regenerating eBPF bindings (`make ebpf-gen`, only when editing `bpf/tracer.c`):**
  `clang`, `bpftool` (`linux-tools-*`), and `libbpf-dev`.
  `sudo apt install -y clang bpftool libbpf-dev linux-tools-$(uname -r)`

## Build
```bash
make build                 # = CGO_ENABLED=0 go build  (static, ~15 MB)
ldd ./sysdiag-analyzer     # -> "not a dynamic executable"
make test
```

### eBPF process tracing (`--enable-ebpf`)
The default binary ships an eBPF stub. The real tracer builds from committed bindings:
```bash
make ebpf                          # build with -tags ebpf (no clang/bpftool needed)
sudo ./sysdiag-analyzer run --enable-ebpf --no-save   # must run as root
```
It aggregates **in-kernel** per cgroup and attributes to units. Per unit:
- exec/exit counts and the **top exec'd binary**
- **abnormal exits** split into signal-killed (with the signal) vs nonzero exit
  (with the code) — e.g. `rc127` = a service repeatedly exec'ing a missing binary
- **OOM kills** (`oom/mark_victim`) attributed to the victim's cgroup
- **fatal signals received** (SIGKILL/SIGTERM)
- **off-CPU / D-state stall** time — blocked on I/O or locks
- **block-I/O device latency** (avg/max) — accurate for synchronous I/O; async
  writeback is attributed to root/kernel (issuing-context limitation)

Per-cgroup **TCP-retransmit** attribution is intentionally omitted: retransmits
fire in softirq context and can't be reliably mapped to a systemd unit via eBPF,
so a per-unit number would be misleading. Use a node TCP exporter for that.

Only regenerate when you change `bpf/tracer.c` (needs the build deps above):
```bash
make ebpf-gen                      # go generate (clang+bpftool+libbpf) then build
```

## Commands
`run` (flags: `--enable-ebpf`, `--analyze-ml`, `--analyze-llm`, `--llm-model`,
`--analyze-full-graph`, `--since`, `--no-save`, `--output rich|json`), `top`
(`--sort mem|cpu|io|limit`, `--interval`, `--count`), `exporter` (`--host/--port/-i`),
`analyze-health`, `analyze-resources`, `analyze-boot`, `analyze-logs` (`--boot`, `--priority`,
`--since`), `analyze-unit <unit>` (focused single-unit report), `show-history` (`--limit`),
`config show`.

## LLM synthesis (`--analyze-llm`)
`[llm].provider` selects the backend:
- **`ollama`** / **`openai`** (or `openai-compatible`) — HTTP to a local or remote endpoint.
- **`claude-code`** — runs the local Claude Code CLI headlessly (`claude -p --output-format
  json`), using your existing Claude Code auth, so **no API key** is needed. `[llm].model`
  is optional (defaults to the CLI's model); `[llm].host` may point at a non-default `claude`
  binary path. Override the model per-run with `--llm-model`.

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
