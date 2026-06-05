# Adaptive baseline anomaly detection (replaces the LSTM bonus)

## Context

The software's intention is to **learn each unit's normal baseline and flag
deviations**. LSTM autoencoders are a poor fit for this data — sparse, irregular,
mostly-stationary per-unit metrics across hundreds of units, where operators want
*interpretable level/rate/trend/seasonal* anomalies, not subtle temporal-sequence-shape
anomalies. They're heavy (TF), opaque (one reconstruction scalar, no attribution),
per-unit-model-explosion, and the `timesteps=5` window can't even capture seasonality.

This plan adds an **adaptive, online statistical baseline** that genuinely *learns*
over time and stays lightweight/interpretable. It supersedes the LSTM bonus.

A baseline here decomposes into four axes; we already cover two and add two:

| Axis | Detector | Status |
|---|---|---|
| Level / rate (spike vs own recent distribution) | `analyze/stats` (median+MAD modified-z over a window) | done |
| Trend (sustained growth → leak) | `analyze/leak` (anon slope) | done |
| **Level with adaptive drift** (online EWMA control limits) | **new `analyze/baseline`** | this plan |
| **Seasonality** (hour-of-day / day-of-week) | **new `analyze/baseline` (optional)** | this plan |

Difference vs the existing `stats` detector: `stats` is **stateless** — it recomputes
from a loaded history window each run. The baseline detector is **stateful/online** —
it persists a tiny per-(unit,metric) EWMA state, updates it with each sample, and only
needs the *current* sample to score. That is what "learning a baseline" means here:
it adapts to slow drift, captures time-of-day patterns, and needs no history reload.

## What it learns

Per `(unit, metric)`:
- **EWMA control chart**: exponentially-weighted mean `μ` and variance `σ²`. Flag when
  the current value is `> μ + k·σ` (one-sided high for resource metrics). Adapts to slow
  drift; `k` from sensitivity.
- **Seasonal buckets (optional)**: one EWMA `μ/σ` per hour-of-day (24) — extendable to
  `day×hour` (168). When the matching bucket is "warm", score against it instead of the
  global EWMA, so a nightly backup spike isn't flagged at 03:00 but *is* at noon.

Counters (cpu, io) are scored as **rates**: the state keeps the previous raw counter +
timestamp and derives `Δ/Δt` online; a negative delta (reboot/reset) resets that metric
without emitting. Gauges (`mem_current`, `mem_anon`, `tasks`) are scored directly.
**Warmup**: a baseline scores only after `min_updates` (default 8); before that it updates
silently. Trend/leaks remain the job of `analyze/leak`.

## How it fits the Go port

New package mirroring the existing `internal/analyze/{stats,leak}`:

```
internal/analyze/baseline/
  baseline.go   # state types, Detect (score+update), EWMA/seasonal math
  store.go      # JSON load/save + prune (persisted under models.directory)
  baseline_test.go
```

### Types (sketch)

```go
package baseline

type ewma struct { N int; Mean, Var float64 }                 // West's EWMV
func (e *ewma) score(x, k float64) (z float64, flag bool) { ... } // pre-update
func (e *ewma) update(x, alpha float64)                    { ... }

type metricState struct {
    Global     ewma
    Seasonal   [24]ewma           // optional hour-of-day buckets
    PrevCtr    *float64           // last raw counter value (rate metrics)
    PrevTS     float64
}

// Store: unit -> metric -> state. Persisted as one JSON file (state is tiny).
type Store struct {
    Units map[string]map[string]*metricState `json:"units"`
}

func Load(path string) *Store
func (s *Store) Save(path string) error
func (s *Store) Prune(seen map[string]bool, ...) // drop long-absent units
```

### Detect — online score + update from the *current* report only

```go
// Detect scores the current per-unit usage against the learned baseline, then
// updates the baseline with it. only/sensitivity/seasonal/alpha from config.
func Detect(s *Store, usage []types.UnitResourceUsage, now float64,
            sensitivity string, seasonal bool, alpha float64,
            only map[string]bool) []types.AnomalyInfo
```
For each unit/metric: derive value (gauge as-is; counter→rate via `PrevCtr/PrevTS`),
pick the seasonal bucket if enabled+warm else the global EWMA, `score()` (pre-update),
flag if `z >= k`, then `update()`. Emit `types.AnomalyInfo{Method:"baseline",
Score:maxZ, ContributingMetrics:{metric:z}}` — the **same schema** the report/exporter
already render, with per-metric attribution.

EWMA update (West's exponentially-weighted mean+variance):
```
diff  = x - Mean
Mean += alpha*diff
Var   = (1-alpha)*(Var + alpha*diff*diff)   // σ = sqrt(Var)
N++
```
Sensitivity → `k`: low=4.0, medium=3.0, high=2.5.

### Wiring (minimal changes to existing code)

- **config** (`internal/config`): `Models.Method` already supports a string; add
  `"baseline"`. New keys: `ewma_alpha` (default 0.3), `seasonal` (bool, default false),
  `min_updates` (default 8). State file: `<Models.Directory>/baseline.json`.
- **run** (`cmd/.../main.go`, `--analyze-ml` block): dispatch on method —
  ```go
  switch cfg.Models.Method {
  case "lstm":      // existing stub
  case "baseline":
      st := baseline.Load(filepath.Join(cfg.Models.Directory, "baseline.json"))
      anomalies := baseline.Detect(st, r.ResourceAnalysis.UnitUsage, nowSec(),
                                   cfg.Models.Sensitivity, cfg.Models.Seasonal, cfg.Models.EWMAAlpha, active)
      _ = st.Save(...)                       // persist the learned state
      r.MLAnalysis = &types.MLAnalysisResult{AnomaliesDetected: anomalies, UnitsAnalyzedCount: len(active)}
  default:          // "statistical" (current default)
      r.MLAnalysis = &types.MLAnalysisResult{AnomaliesDetected: stats.DetectAnomalies(...)}
  }
  // leak.Detect(...) still runs regardless (trend axis).
  ```
- **exporter** (`internal/exporter`): unchanged — it already emits `unit_anomaly_score`
  from `MLAnalysisResult`. (Optionally also call `baseline.Detect` on its periodic refresh
  so the persistent baseline keeps learning between `run`s.)
- **reuse**: counter→rate logic and sensitivity mapping already exist in `analyze/stats`;
  `types.AnomalyInfo` and `internal/report` rendering are unchanged.

### Persistence & lifecycle
- One small JSON file (`baseline.json`) under the models dir: hundreds of units × a few
  metrics × a few floats (+24 buckets if seasonal) — well under a megabyte.
- Updated every `run --analyze-ml` (and/or each exporter refresh) — that *is* the learning
  loop. `Prune` drops units absent for K consecutive observations to bound growth.
- Each run is cheap: load small JSON, score current sample, update, save — **no history
  reload**, unlike the window-based `stats` detector.

## Tests
- `ewma.score/update`: feed a steady stream → σ stabilizes, no flag; inject a spike →
  z ≥ k; verify drift tracking (slowly rising mean isn't flagged).
- Counter→rate reset: a counter drop yields no rate (no false anomaly).
- Warmup: < `min_updates` → silent.
- Seasonal: a value normal for its hour bucket isn't flagged even if high vs the global mean.
- Store round-trip (Load→Save) and Prune.

## Effort & why this over LSTM
- **~3–5 days** (vs multi-week LSTM): the EWMA/seasonal math is small and pure-Go
  (no gorgonia, no `-tags`), the wiring mirrors the existing detectors, and it's fully
  unit-testable. Works from ~8 samples, interpretable per-metric, adapts to drift, and
  captures seasonality the `timesteps=5` LSTM never could.

## Optional follow-up (not required)
If single-metric baselines miss *combinations* (cpu+io jointly unusual), add a pooled
**IsolationForest / robust-covariance** check as a separate detector — lighter than LSTM,
no per-unit training. Add only if real misses appear in practice.
