# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
