# tests/test_integration_live.py
# -*- coding: utf-8 -*-
"""
Live integration tests that run the core analyzers against the REAL systemd on
the host (no mocks). They auto-skip when systemd is unavailable, so they run on
this host and on a systemd-enabled CI job while skipping cleanly elsewhere.

These convert "the unit tests pass" into "the analyzers actually parse real
systemd output" — the gap the heavily-mocked unit suite cannot cover.
"""
import shutil
from pathlib import Path

import pytest

from sysdiag_analyzer.modules import health, logs, boot, resources
from sysdiag_analyzer.datatypes import (
    HealthAnalysisResult,
    LogAnalysisResult,
    BootAnalysisResult,
    SystemResourceUsage,
    UnitHealthInfo,
)

_HAS_SYSTEMD = shutil.which("systemctl") is not None and Path("/run/systemd/system").is_dir()

pytestmark = pytest.mark.skipif(not _HAS_SYSTEMD, reason="requires a live systemd host")


def test_live_system_wide_usage():
    """psutil-backed system metrics return real, sane values."""
    usage = resources.get_system_wide_usage()
    assert isinstance(usage, SystemResourceUsage)
    assert usage.cpu_percent is not None and usage.cpu_percent >= 0.0
    assert usage.mem_percent is not None and 0.0 <= usage.mem_percent <= 100.0


def test_live_list_units_and_health():
    """`systemctl list-units` JSON parses into units; health analysis runs on them."""
    units, err = health._get_all_units_json()
    assert err is None, f"listing units failed: {err}"
    assert isinstance(units, list) and len(units) > 0
    assert all(isinstance(u, UnitHealthInfo) and u.name for u in units)

    # Run the real health pipeline (fallback path, no DBus) on a subset for speed.
    subset = units[:25]
    result = health.analyze_health(subset, dbus_manager=None)
    assert isinstance(result, HealthAnalysisResult)
    assert result.all_units_count == len(subset)
    # Returned problem lists are well-formed (may legitimately be empty).
    assert isinstance(result.failed_units, list)
    assert isinstance(result.flapping_units, list)


def test_live_log_analysis():
    """Journal log analysis runs against the real journal without crashing."""
    result = logs.analyze_general_logs()
    assert isinstance(result, LogAnalysisResult)
    assert result.total_entries_analyzed >= 0
    assert isinstance(result.detected_patterns, list)


def test_live_boot_analysis():
    """`systemd-analyze`-backed boot analysis returns a populated result."""
    result = boot.analyze_boot()
    assert isinstance(result, BootAnalysisResult)
    # Either we parsed boot timing, or we recorded why not — never silent.
    assert result.times is not None or result.blame_error or result.critical_chain_error
    assert isinstance(result.blame, list)
