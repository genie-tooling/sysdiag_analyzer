# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.14.0] - 2026-06-04

### Added
- **`top` is now a real live monitor.** Each refresh derives **CPU %** and **I/O
  rates** from the cumulative counters; memory is split into **anon** (process
  memory) vs reclaimable **cache** via `memory.stat`, with a trend arrow; open
  **file-descriptor** counts are shown for the displayed units; and the header
  shows **system-wide network rate**. A unit whose anonymous memory climbs steadily
  across the rolling window is flagged **`LEAK?`** — anon-based, so reclaimable page
  cache isn't mistaken for a leak, and it resets on restart.
- `UnitResourceUsage` gains `memory_anon_bytes` / `memory_file_bytes`; `resources`
  gains `get_cgroup_fd_count` and `_parse_cgroup_memory_stat`; `tui` gains a
  `TopState` (rolling history → rates/trends/leak flag).

### Changed
- "Cgroup directory not present" (inactive services, idle sockets) is now logged at
  debug instead of warning, reducing noise in `analyze-resources` / `run`.

## [0.13.1] - 2026-06-03

### Fixed
- `top`: analyzer log warnings no longer flash over the full-screen live view on
  each refresh — logging is silenced for the duration of the loop and restored on exit.

## [0.13.0] - 2026-06-03

### Changed
- **Per-unit cgroup data no longer requires `dbus-python`.** `get_unit_resource_usage`
  resolves each unit's cgroup path via DBus when available, otherwise via a single
  batched `systemctl show -p Id -p ControlGroup` call. So `analyze-resources`, `run`,
  and `top` show per-unit memory / limits / CPU / I/O with just `systemctl` access —
  no compiler or `[native]` build needed (which previously failed on, e.g., uv's
  standalone Python). DBus remains a marginally faster option for the one-time path
  resolution, and the result is cached for live refresh (`top`). `analyze_resources`
  no longer short-circuits per-unit collection when DBus is absent.

## [0.12.0] - 2026-06-03

### Added
- **`top` — a live, top-like view.** `sysdiag-analyzer top` shows a continuously
  refreshing table of per-unit cgroup usage (memory, CPU, I/O, tasks) with the
  memory **limit** and **%-of-limit** columns, sortable by `mem`/`cpu`/`io`/`limit`,
  failed units highlighted in red, and uncapped cgroups flagged `none`. Built on
  rich.Live (no new dependencies). The expensive DBus cgroup-path lookup is cached
  so each refresh only re-reads the cheap /sys files; `get_unit_resource_usage`
  gained an optional `cgroup_path_cache` parameter to support this.

## [0.11.0] - 2026-06-03

### Changed
- **Anomaly detection is useful out of the box.** The default method is now a
  **statistical** detector — a robust per-unit/per-metric median + MAD modified
  z-score that needs no training step, no persisted model, and no heavyweight
  dependencies. It runs on a base install (no `[ml]` extra / no TensorFlow) and
  engages after ~a dozen reports. The LSTM autoencoder becomes an opt-in "deep"
  mode via `[models].method = "lstm"`.

### Added
- **Counter→rate conversion.** Cumulative cgroup counters (`cpu_usage_nsec`,
  `io_read/write_bytes`) are converted to per-second rates before scoring, so the
  detector models behaviour rather than uptime and a reboot (counter reset) is no
  longer mistaken for an anomaly.
- **Per-feature attribution.** Anomalies report which metric(s) deviated and by how
  much (z-score), shown in the rich/JSON report. `AnomalyInfo` gains `method` and
  `contributing_metrics`.
- **Tuning knobs:** `[models].method`, `[models].sensitivity` (low|medium|high),
  and `[models].history_window`.

### Notes
- The LSTM path still trains on raw counter *levels*; migrating it to rates is
  future work. The statistical default is unaffected.

## [0.10.0] - 2026-06-03

### Added
- **Per-unit memory limits & utilization.** Resource analysis now reads each unit's
  cgroup `memory.max` and `memory.high` alongside `memory.current`. The rich report's
  Top Memory Consumers table gains **Limit (max)** and **% Limit** columns — `none`
  flags a cgroup with no hard limit, and the percentage turns yellow/red as usage
  approaches the cap. `UnitResourceUsage` gains `memory_max_bytes` / `memory_high_bytes`
  and a `memory_percent_of_limit` property.
- **Exporter metrics** `sysdiag_analyzer_unit_memory_current_bytes`,
  `…_unit_memory_max_bytes`, and `…_unit_memory_high_bytes` (labelled by `unit`),
  emitted for units that have a configured limit or are among the top memory consumers.
  A unit with a `current` series but no `max` series is one whose growth is uncapped —
  useful for spotting e.g. a `virtiofsd`/VM scope that escaped its intended `MemoryMax`.

## [0.9.0] - 2026-06-03

### Packaging
- **Honest dependencies.** The heavyweight/compiled libraries are no longer forced
  on every install. The base `pip install` now pulls only a small pure-Python core
  (`typer`, `rich`, `psutil`, `pygments`); TensorFlow, pandas, scikit-learn, joblib,
  prometheus-client, networkx and the native systemd/DBus bindings moved to their
  existing optional extras (`[ml]`, `[exporter]`, `[full-graph]`, `[native]`, …).
  This makes the `HAS_*` import guards meaningful again and keeps a base install tiny.
- `requires-python` is now `>=3.11`, matching the CI matrix (3.11–3.13); dropped the
  `tomli` dependency in favour of the stdlib `tomllib`.
- Fixed placeholder project metadata (author, homepage, bug tracker).
- The `[ebpf]` extra no longer depends on the unrelated PyPI `bcc` package. BCC's
  Python bindings are only available from the distro (`python3-bpfcc` /
  `python3-bcc`), so `[ebpf]` is now a documentation-only group and the README /
  MAN page point at the correct system packages.

### Added
- **OpenAI-compatible LLM provider.** `provider = "openai"` / `"openai-compatible"`
  targets any `/v1/chat/completions` endpoint (OpenAI, vLLM, llama.cpp, LocalAI) via
  the new `[openai]` extra. New `[llm].api_key` config (falls back to `OPENAI_API_KEY`).
- **`run --since`** is now implemented: restricts log analysis to a `journalctl
  --since` time window instead of being a no-op.
- **eBPF per-unit aggregation.** `EBPFAnalysisResult.units_with_execs` /
  `units_with_exits` are now populated by resolving each event's cgroup id to its
  owning systemd unit.
- Real end-to-end tests for the headline features: an LSTM train → persist → reload →
  detect round-trip (no mocked worker/model), real LLM orchestration with only the
  network boundary stubbed, and live-systemd integration tests (auto-skip off-systemd).

### Fixed
- **cgroup v2 `io.stat` parsing.** The parser skipped the per-device lines that
  actually carry `rbytes`/`wbytes`, so per-unit I/O was always reported as `0` on
  real hosts. It now sums the counters across devices.
- **Boot-time parsing.** `systemd-analyze` compound durations (`696ms`,
  `1min 21.085s`, `2min 389ms`, `1h …`) were not matched, losing the entire boot
  timing breakdown on slower boots. The duration regex now handles multi-token
  `h/min/s/ms/us` values.
- **Boot-blame memory blow-up.** The `journalctl` fallback loaded the entire boot
  journal into memory (millions of lines → OOM). It now filters server-side with
  `--grep` to just the unit start/stop lines (~3 orders of magnitude smaller).
- `run_subprocess` now applies a default timeout so a hung
  `systemctl`/`journalctl`/`systemd-analyze` can't wedge the analysis.
- Resource unit tests no longer hard-fail on machines without `dbus-python`; they
  skip cleanly like the other DBus-gated tests.
