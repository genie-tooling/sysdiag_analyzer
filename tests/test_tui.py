# tests/test_tui.py
# -*- coding: utf-8 -*-
"""Tests for the top-like live view rendering (pure render + sorting)."""
import logging
from unittest.mock import patch

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


class _DummyLive:
    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def update(self, *a, **k):
        pass


def test_run_top_silences_then_restores_logging():
    """The live loop disables logging (so warnings don't flash over the screen)
    and must restore it on exit."""
    with patch.object(tui, "Live", _DummyLive), \
         patch("sysdiag_analyzer.modules.health.HAS_DBUS", False), \
         patch("sysdiag_analyzer.modules.health._get_all_units_json", return_value=([], None)), \
         patch("sysdiag_analyzer.modules.resources.get_system_wide_usage", side_effect=KeyboardInterrupt):
        tui.run_top({}, interval=0)
    # Global logging disable level is back to 0 (NOTSET).
    assert logging.getLogger().manager.disable == 0


# --- TopState: rates, trends, leak detection ---

def test_topstate_cpu_pct_and_io_rate():
    st = tui.TopState()
    st.update([UnitResourceUsage(name="a", cpu_usage_nsec=0, io_read_bytes=0, io_write_bytes=0)], now=0.0)
    # 1s later: +0.5s CPU (5e8 ns) -> 50%; +1 MiB read.
    later = UnitResourceUsage(name="a", cpu_usage_nsec=500_000_000, io_read_bytes=1024 * 1024, io_write_bytes=0)
    d = st.update([later], now=1.0)["a"]
    assert abs(d.cpu_pct - 50.0) < 1e-6
    assert abs(d.io_read_rate - 1024 * 1024) < 1e-6


def test_topstate_flags_anon_leak_and_resets_on_drop():
    st = tui.TopState(window=4)
    base = 100 * 1024 * 1024
    d = {}
    for i in range(4):  # steady climb of 50 MiB/step across a full window
        d = st.update([UnitResourceUsage(name="leak", memory_anon_bytes=base + i * 50 * 1024 * 1024)], now=float(i))
    assert d["leak"].leaking is True
    # A drop (restart) clears the suspicion.
    d = st.update([UnitResourceUsage(name="leak", memory_anon_bytes=base)], now=4.0)
    assert d["leak"].leaking is False


def test_topstate_no_leak_when_flat():
    st = tui.TopState(window=4)
    d = {}
    for i in range(4):
        d = st.update([UnitResourceUsage(name="flat", memory_anon_bytes=100 * 1024 * 1024)], now=float(i))
    assert d["flat"].leaking is False


def test_topstate_net_rate():
    st = tui.TopState()
    assert st.net_rate(SystemResourceUsage(net_io_sent_bytes=0, net_io_recv_bytes=0), 0.0) == (None, None)
    up, down = st.net_rate(SystemResourceUsage(net_io_sent_bytes=1000, net_io_recv_bytes=2000), 1.0)
    assert up == 1000.0 and down == 2000.0


def test_build_top_view_shows_cpu_pct_leak_and_net():
    units = [UnitResourceUsage(name="x.service", memory_current_bytes=GIB, memory_anon_bytes=GIB)]
    derived = {"x.service": tui.TopDerived(cpu_pct=42.0, leaking=True, mem_trend="▲", fd_count=128)}
    out = _render(tui.build_top_view(None, units, derived=derived, net_rate=(1000.0, 2000.0)))
    assert "42.0" in out          # CPU%
    assert "LEAK?" in out         # leak badge
    assert "leaks?:1" in out      # header leak count
    assert "128" in out           # fd count
    assert "Net" in out           # system net rate in header
