# src/sysdiag_analyzer/ml_baseline.py
"""
Dependency-free (stdlib-only) robust statistical anomaly detector.

This is the default anomaly-detection method. Unlike the LSTM autoencoder in
`ml_engine`, it needs no training step, no persisted model, and no heavyweight
dependencies (pandas / scikit-learn / TensorFlow) — so it works out of the box
from a handful of historical reports on a base install.

For each unit it builds a per-metric baseline from that unit's own recent
history and scores the most recent sample with a robust *modified z-score*
(median + MAD). Cumulative cgroup counters (CPU time, I/O bytes) are converted
to per-second rates first, so the detector models behaviour rather than uptime
and a counter reset (reboot) is not mistaken for an anomaly.
"""
from __future__ import annotations

import logging
import statistics
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .datatypes import AnomalyInfo, MemoryLeakInfo

log = logging.getLogger(__name__)

# Modified z-score thresholds by sensitivity. 3.5 is the classic Iglewicz-Hoaglin
# outlier cutoff; lower = more sensitive (flags smaller deviations).
SENSITIVITY_THRESHOLDS: Dict[str, float] = {"low": 5.0, "medium": 3.5, "high": 2.5}
DEFAULT_SENSITIVITY = "medium"

# Minimum baseline samples (excluding the current one) before a unit is scored.
# Below this we stay silent rather than emit cold-start false positives.
MIN_BASELINE_SAMPLES = 8

# Sentinel z-score for a perfectly constant baseline that the current sample
# departs from. A large finite value (not inf) keeps reports JSON-serialisable.
_CONSTANT_BASELINE_Z = 1_000_000.0

# Default number of recent reports to load as the baseline window.
DEFAULT_HISTORY_WINDOW = 30

# Gauge metrics are used as-is; counter metrics are converted to per-second rates.
_GAUGE_METRICS = ("mem_current_bytes", "tasks_current")
_COUNTER_RATE_NAMES = {
    "cpu_usage_nsec": "cpu_usage_rate",
    "io_read_bytes": "io_read_rate",
    "io_write_bytes": "io_write_rate",
}


def _parse_timestamp(value: Any) -> Optional[float]:
    """Parse a report_timestamp (ISO-8601 string or epoch number) to epoch seconds."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except (ValueError, TypeError):
        return None


def _modified_zscore(current: float, baseline: List[float]) -> Optional[float]:
    """Robust modified z-score of `current` against `baseline`.

    Uses median + MAD (robust to the very outliers we are hunting). Falls back to
    stdev when MAD is zero, and to an exact-equality test for a constant baseline.
    Returns None when the baseline is too small to judge.
    """
    if len(baseline) < MIN_BASELINE_SAMPLES:
        return None
    med = statistics.median(baseline)
    mad = statistics.median([abs(x - med) for x in baseline])
    if mad > 0:
        return 0.6745 * (current - med) / mad
    # Degenerate (near-constant) baseline.
    try:
        sd = statistics.stdev(baseline)
    except statistics.StatisticsError:
        sd = 0.0
    if sd > 0:
        return (current - med) / sd
    # Perfectly constant baseline: no deviation is normal, any deviation is extreme.
    return 0.0 if current == med else _CONSTANT_BASELINE_Z


def _build_metric_series(samples: List[Dict[str, Any]]) -> Dict[str, List[Optional[float]]]:
    """Build per-metric value series for a unit's time-ordered samples.

    Gauges map straight through; counters become per-second rates (with the first
    sample and any counter reset yielding None for that step).
    """
    series: Dict[str, List[Optional[float]]] = {}
    for name in _GAUGE_METRICS:
        series[name] = [
            float(s[name]) if isinstance(s.get(name), (int, float)) else None
            for s in samples
        ]
    for counter, rate_name in _COUNTER_RATE_NAMES.items():
        rates: List[Optional[float]] = [None]  # first sample has no rate
        for i in range(1, len(samples)):
            prev, cur = samples[i - 1], samples[i]
            pv, cv, dt = prev.get(counter), cur.get(counter), cur["ts"] - prev["ts"]
            if isinstance(pv, (int, float)) and isinstance(cv, (int, float)) and dt > 0:
                delta = cv - pv
                rates.append(delta / dt if delta >= 0 else None)  # negative = reset
            else:
                rates.append(None)
        series[rate_name] = rates
    return series


def detect_anomalies_statistical(
    feature_dicts: List[Dict[str, Any]],
    sensitivity: str = DEFAULT_SENSITIVITY,
    only_units: Optional[Set[str]] = None,
) -> List[AnomalyInfo]:
    """Flag units whose latest sample deviates from their own recent history.

    Args:
        feature_dicts: feature dicts from `features.extract_features` (resource
            samples across several reports, the last being the current one).
        sensitivity: "low" | "medium" | "high" (maps to a modified z-score cutoff).
        only_units: if given, restrict scoring to these unit names.

    Returns:
        AnomalyInfo list, most anomalous first, each annotated with the metric(s)
        that exceeded the threshold and their z-scores.
    """
    threshold = SENSITIVITY_THRESHOLDS.get(sensitivity, SENSITIVITY_THRESHOLDS[DEFAULT_SENSITIVITY])

    by_unit: Dict[str, List[Dict[str, Any]]] = {}
    for feat in feature_dicts:
        if feat.get("source") != "resource_analysis":
            continue
        unit = feat.get("unit_name")
        if not unit or (only_units is not None and unit not in only_units):
            continue
        ts = _parse_timestamp(feat.get("report_timestamp"))
        if ts is None:
            continue
        by_unit.setdefault(unit, []).append({"ts": ts, **feat})

    anomalies: List[AnomalyInfo] = []
    for unit, samples in by_unit.items():
        if len(samples) < MIN_BASELINE_SAMPLES + 1:
            continue  # not enough history yet -> stay silent (no cold-start noise)
        samples.sort(key=lambda s: s["ts"])

        contributing: Dict[str, float] = {}
        for metric, values in _build_metric_series(samples).items():
            current = values[-1]
            if current is None:
                continue
            baseline = [v for v in values[:-1] if v is not None]
            z = _modified_zscore(current, baseline)
            # One-sided: we care about spikes (high usage), not drops.
            if z is not None and z >= threshold:
                contributing[metric] = round(z, 2)

        if contributing:
            score = max(contributing.values())
            anomalies.append(
                AnomalyInfo(
                    unit_name=unit,
                    score=float(score),
                    method="statistical",
                    contributing_metrics=contributing,
                )
            )
            log.info(
                f"Statistical anomaly for '{unit}': "
                + ", ".join(f"{m} (z={z})" for m, z in contributing.items())
            )

    anomalies.sort(key=lambda a: a.score, reverse=True)
    return anomalies


# --- Memory-leak detection (sustained anon-memory growth over history) ---

LEAK_MIN_SAMPLES = 6
LEAK_MIN_SLOPE_BYTES_PER_HOUR = 10 * 1024 * 1024  # 10 MiB/hour
LEAK_MIN_R2 = 0.8
_LEAK_RESET_DROP_FRAC = 0.7  # anon dropping below 70% of the prior sample = restart


def _linear_fit(xs: List[float], ys: List[float]) -> Tuple[float, float]:
    """Least-squares fit; returns (slope, r_squared)."""
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return 0.0, 0.0
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    ss_tot = sum((y - my) ** 2 for y in ys)
    if ss_tot == 0:
        return slope, 1.0  # perfectly flat (slope ~0)
    intercept = my - slope * mx
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
    return slope, 1.0 - ss_res / ss_tot


def detect_memory_leaks(
    feature_dicts: List[Dict[str, Any]],
    min_samples: int = LEAK_MIN_SAMPLES,
    min_slope_bytes_per_hour: float = LEAK_MIN_SLOPE_BYTES_PER_HOUR,
    min_r2: float = LEAK_MIN_R2,
    only_units: Optional[Set[str]] = None,
) -> Tuple[List[MemoryLeakInfo], int]:
    """Flag units whose anonymous memory grows steadily over the report history.

    For each unit, fit a line to its anon-memory series (restarting the window at
    a large drop, i.e. a service restart) and flag a sustained positive slope with
    a good fit. Anon-based, so reclaimable page cache is not mistaken for a leak.

    Returns (suspected_leaks, units_analyzed).
    """
    by_unit: Dict[str, List[Tuple[float, float]]] = {}
    for feat in feature_dicts:
        if feat.get("source") != "resource_analysis":
            continue
        unit = feat.get("unit_name")
        anon = feat.get("mem_anon_bytes")
        ts = _parse_timestamp(feat.get("report_timestamp"))
        if (
            not unit
            or (only_units is not None and unit not in only_units)
            or not isinstance(anon, (int, float))
            or ts is None
        ):
            continue
        by_unit.setdefault(unit, []).append((ts, float(anon)))

    leaks: List[MemoryLeakInfo] = []
    analyzed = 0
    for unit, points in by_unit.items():
        points.sort(key=lambda p: p[0])
        # Restart the window at the last large drop (service restart / counter reset).
        start = 0
        for i in range(1, len(points)):
            if points[i][1] < points[i - 1][1] * _LEAK_RESET_DROP_FRAC:
                start = i
        seg = points[start:]
        if len(seg) < min_samples:
            continue
        analyzed += 1
        t0 = seg[0][0]
        xs = [t - t0 for t, _ in seg]
        ys = [y for _, y in seg]
        slope_per_sec, r2 = _linear_fit(xs, ys)
        slope_per_hour = slope_per_sec * 3600.0
        growth = ys[-1] - ys[0]
        if slope_per_hour >= min_slope_bytes_per_hour and r2 >= min_r2 and growth > 0:
            leaks.append(
                MemoryLeakInfo(
                    unit_name=unit,
                    slope_bytes_per_hour=slope_per_hour,
                    growth_bytes=int(growth),
                    r_squared=round(r2, 3),
                    samples=len(seg),
                )
            )
            log.info(
                f"Suspected memory leak in '{unit}': "
                f"{slope_per_hour / (1024 * 1024):.1f} MiB/hour (R^2={r2:.2f}, n={len(seg)})"
            )
    leaks.sort(key=lambda lk: lk.slope_bytes_per_hour, reverse=True)
    return leaks, analyzed
