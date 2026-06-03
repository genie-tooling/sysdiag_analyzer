# tests/test_tui.py
# -*- coding: utf-8 -*-
"""Tests for the top-like live view rendering (pure render + sorting)."""
from rich.console import Console

from sysdiag_analyzer import tui
from sysdiag_analyzer.datatypes import SystemResourceUsage, UnitResourceUsage

GIB = 1024 * 1024 * 1024


def _render(group) -> str:
    console = Console(record=True, width=120)
    console.print(group)
    return console.export_text()


def test_build_top_view_shows_limits_system_and_failed():
    sys_u = SystemResourceUsage(cpu_percent=12.0, mem_percent=88.0, swap_percent=5.0)
    units = [
        UnitResourceUsage(name="machine.scope", memory_current_bytes=20 * GIB),  # uncapped
        UnitResourceUsage(name="capped.service", memory_current_bytes=6 * GIB, memory_max_bytes=8 * GIB),
        UnitResourceUsage(name="dead.service", memory_current_bytes=1024),
    ]
    out = _render(tui.build_top_view(sys_u, units, failed_units={"dead.service"}, sort_key="mem", count=10))
    assert "sysdiag top" in out
    assert "Mem 88%" in out
    assert "machine.scope" in out
    assert "none" in out      # uncapped unit shows no hard limit
    assert "%" in out         # capped unit shows a percentage
    assert "failed:1" in out


def test_sort_units_by_limit_puts_highest_pct_first_unlimited_last():
    units = [
        UnitResourceUsage(name="a", memory_current_bytes=100, memory_max_bytes=1000),   # 10%
        UnitResourceUsage(name="b", memory_current_bytes=900, memory_max_bytes=1000),   # 90%
        UnitResourceUsage(name="c", memory_current_bytes=5000),                          # no limit
    ]
    ordered = [u.name for u in tui._sort_units(units, "limit")]
    assert ordered[0] == "b"
    assert ordered[-1] == "c"


def test_sort_units_by_cpu_and_mem():
    units = [
        UnitResourceUsage(name="a", cpu_usage_nsec=10, memory_current_bytes=1),
        UnitResourceUsage(name="b", cpu_usage_nsec=999, memory_current_bytes=2),
    ]
    assert [u.name for u in tui._sort_units(units, "cpu")][0] == "b"
    assert [u.name for u in tui._sort_units(units, "mem")][0] == "b"
