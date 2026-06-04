# tests/test_ml_baseline.py
# -*- coding: utf-8 -*-
"""Tests for the stdlib statistical anomaly detector (ml_baseline)."""
import datetime

from sysdiag_analyzer import ml_baseline

_BASE = datetime.datetime(2026, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
MIB = 1024 * 1024
GIB = 1024 * 1024 * 1024


def _sample(unit, i, *, mem, cpu, ior=0, iow=0, tasks=5):
    """One resource_analysis feature dict, samples spaced 60s apart."""
    return {
        "report_timestamp": (_BASE + datetime.timedelta(minutes=i)).isoformat(),
        "boot_id": "boot1",
        "unit_name": unit,
        "source": "resource_analysis",
        "cpu_usage_nsec": cpu,
        "mem_current_bytes": mem,
        "io_read_bytes": ior,
        "io_write_bytes": iow,
        "tasks_current": tasks,
    }


def test_steady_series_no_anomaly():
    n = ml_baseline.MIN_BASELINE_SAMPLES + 5
    feats = [_sample("steady.service", i, mem=100 * MIB, cpu=i * 10**9) for i in range(n)]
    assert ml_baseline.detect_anomalies_statistical(feats) == []


def test_cumulative_cpu_growth_is_not_an_anomaly_but_a_rate_spike_is():
    """Counter->rate conversion: linearly-growing cpu_usage_nsec (constant rate)
    must NOT flag, but a sudden burst in the *rate* must."""
    n = ml_baseline.MIN_BASELINE_SAMPLES + 5
    feats, cpu = [], 0
    for i in range(n):
        cpu += 2 * 10**9  # constant +2s CPU per interval -> constant rate
        feats.append(_sample("cpu.service", i, mem=100 * MIB, cpu=cpu))
    assert ml_baseline.detect_anomalies_statistical(feats) == []

    feats_spike = [dict(f) for f in feats]
    feats_spike[-1]["cpu_usage_nsec"] = feats_spike[-2]["cpu_usage_nsec"] + 200 * 10**9
    res = ml_baseline.detect_anomalies_statistical(feats_spike)
    assert len(res) == 1
    assert res[0].unit_name == "cpu.service"
    assert "cpu_usage_rate" in res[0].contributing_metrics


def test_memory_spike_flagged_with_attribution():
    n = ml_baseline.MIN_BASELINE_SAMPLES + 5
    # Bounded mem noise so MAD > 0 and the spike yields a large finite z-score.
    feats = [_sample("spike.service", i, mem=(100 + (i % 7)) * MIB, cpu=i * 10**9) for i in range(n)]
    feats[-1]["mem_current_bytes"] = 5 * GIB
    res = ml_baseline.detect_anomalies_statistical(feats, sensitivity="medium")
    assert len(res) == 1
    a = res[0]
    assert a.unit_name == "spike.service"
    assert a.method == "statistical"
    assert "mem_current_bytes" in a.contributing_metrics
    assert a.score >= ml_baseline.SENSITIVITY_THRESHOLDS["medium"]


def test_cold_start_stays_silent():
    # Exactly MIN_BASELINE_SAMPLES samples -> below the MIN+1 needed to score.
    feats = [_sample("new.service", i, mem=100 * MIB, cpu=i * 10**9)
             for i in range(ml_baseline.MIN_BASELINE_SAMPLES)]
    feats[-1]["mem_current_bytes"] = 9 * GIB  # huge, but not enough history
    assert ml_baseline.detect_anomalies_statistical(feats) == []


def test_counter_reset_not_flagged():
    """A reboot resets cumulative counters; the negative delta yields no rate
    for that step, so it must not be reported as an anomaly."""
    n = ml_baseline.MIN_BASELINE_SAMPLES + 5
    feats = [_sample("svc", i, mem=100 * MIB, cpu=i * 10**9, ior=i * 1000) for i in range(n)]
    feats[-1]["cpu_usage_nsec"] = 5 * 10**8     # counter reset (drops)
    feats[-1]["io_read_bytes"] = 500
    assert ml_baseline.detect_anomalies_statistical(feats) == []


def _moderate_baseline(unit):
    # MAD = 2 MiB (median of deviations from median 100 MiB).
    mems = [100, 102, 98, 101, 99, 103, 97, 100, 102, 98]
    return [_sample(unit, i, mem=m * MIB, cpu=i * 10**9) for i, m in enumerate(mems)]


def test_sensitivity_levels_are_monotonic():
    # moderate -> z~4.0 (current 112 MiB, MAD 2 MiB); big -> z~34 (current 200 MiB).
    feats = _moderate_baseline("moderate.svc") + [_sample("moderate.svc", 10, mem=112 * MIB, cpu=10 * 10**9)]
    feats += _moderate_baseline("big.svc") + [_sample("big.svc", 10, mem=200 * MIB, cpu=10 * 10**9)]

    hi = {a.unit_name for a in ml_baseline.detect_anomalies_statistical(feats, "high")}
    med = {a.unit_name for a in ml_baseline.detect_anomalies_statistical(feats, "medium")}
    lo = {a.unit_name for a in ml_baseline.detect_anomalies_statistical(feats, "low")}

    assert {"big.svc"}.issubset(lo) and {"big.svc"}.issubset(med) and {"big.svc"}.issubset(hi)
    assert "moderate.svc" not in lo          # z~4.0 < 5.0
    assert "moderate.svc" in med             # z~4.0 >= 3.5
    assert "moderate.svc" in hi              # z~4.0 >= 2.5


def _anon_sample(unit, i, anon, step_minutes=60):
    return {
        "report_timestamp": (_BASE + datetime.timedelta(minutes=i * step_minutes)).isoformat(),
        "unit_name": unit,
        "source": "resource_analysis",
        "mem_anon_bytes": anon,
    }


def test_detect_memory_leaks_flags_linear_growth():
    # +100 MiB/hour across 8 hourly samples -> clear leak.
    feats = [_anon_sample("leaky.service", i, (100 + i * 100) * MIB) for i in range(8)]
    leaks, analyzed = ml_baseline.detect_memory_leaks(feats)
    assert analyzed == 1
    assert len(leaks) == 1
    lk = leaks[0]
    assert lk.unit_name == "leaky.service"
    assert lk.slope_bytes_per_hour > 90 * MIB
    assert lk.r_squared > 0.99
    assert lk.samples == 8


def test_detect_memory_leaks_ignores_flat():
    feats = [_anon_sample("flat.service", i, 500 * MIB) for i in range(8)]
    leaks, analyzed = ml_baseline.detect_memory_leaks(feats)
    assert leaks == []
    assert analyzed == 1  # analyzed but not flagged


def test_detect_memory_leaks_resets_on_restart():
    # 8 samples climbing, then a restart (drop) with only 3 post-restart samples.
    feats = [_anon_sample("svc", i, (100 + i * 100) * MIB) for i in range(8)]
    feats += [_anon_sample("svc", 8 + j, (100 + j * 100) * MIB) for j in range(3)]
    leaks, analyzed = ml_baseline.detect_memory_leaks(feats)
    # Only the post-restart tail (3 samples) is considered -> below min_samples.
    assert leaks == []
    assert analyzed == 0


def test_detect_memory_leaks_insufficient_samples():
    feats = [_anon_sample("svc", i, (100 + i * 100) * MIB) for i in range(4)]
    leaks, analyzed = ml_baseline.detect_memory_leaks(feats)
    assert leaks == [] and analyzed == 0


def test_only_units_filter():
    n = ml_baseline.MIN_BASELINE_SAMPLES + 5
    feats = [_sample("a.svc", i, mem=(100 + (i % 5)) * MIB, cpu=i * 10**9) for i in range(n)]
    feats += [_sample("b.svc", i, mem=(100 + (i % 5)) * MIB, cpu=i * 10**9) for i in range(n)]
    feats[n - 1]["mem_current_bytes"] = 9 * GIB   # spike a.svc's latest
    feats[-1]["mem_current_bytes"] = 9 * GIB      # spike b.svc's latest
    res = ml_baseline.detect_anomalies_statistical(feats, only_units={"a.svc"})
    assert {a.unit_name for a in res} == {"a.svc"}
