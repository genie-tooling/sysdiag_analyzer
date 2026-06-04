# src/sysdiag_analyzer/tui.py
"""A live, top-like view of per-unit cgroup resource usage.

Built on rich.Live (no extra dependencies). The expensive DBus/systemctl cgroup
path lookup is resolved once and cached, so each refresh only re-reads the cheap
/sys/fs/cgroup files. A small rolling history (TopState) turns the cumulative
counters into rates (CPU %, I/O/s), tracks anon-memory trend, and raises an
in-session "LEAK?" flag when a unit's anonymous memory climbs steadily.
"""
from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from rich.console import Console, Group
from rich.live import Live
from rich.table import Table
from rich.text import Text

from .datatypes import SystemResourceUsage, UnitResourceUsage
from .output import _format_bytes

SORT_KEYS = ("mem", "cpu", "limit", "io")
_UNIT_REFRESH_EVERY = 10  # re-fetch the unit list every N refresh ticks


@dataclass
class _Sample:
    ts: float
    cpu_nsec: Optional[int]
    anon: Optional[int]
    io_read: Optional[int]
    io_write: Optional[int]


@dataclass
class TopDerived:
    """Per-unit values derived from the rolling history."""
    cpu_pct: Optional[float] = None
    io_read_rate: Optional[float] = None   # bytes/sec
    io_write_rate: Optional[float] = None
    mem_trend: str = ""                     # "▲" rising / "▼" falling / "" flat
    leaking: bool = False
    fd_count: Optional[int] = None


class TopState:
    """Rolling per-unit history used to derive rates, trends and leak flags."""

    def __init__(
        self,
        window: int = 8,
        leak_min_growth_bytes: int = 16 * 1024 * 1024,
        leak_min_growth_frac: float = 0.05,
        leak_max_dips: int = 1,
    ):
        self.window = window
        self.leak_min_growth_bytes = leak_min_growth_bytes
        self.leak_min_growth_frac = leak_min_growth_frac
        self.leak_max_dips = leak_max_dips
        self._hist: Dict[str, Deque[_Sample]] = {}
        self._net_prev: Optional[Tuple[float, int, int]] = None

    def update(self, unit_usages: List[UnitResourceUsage], now: float) -> Dict[str, TopDerived]:
        derived: Dict[str, TopDerived] = {}
        live_names = set()
        for u in unit_usages:
            live_names.add(u.name)
            hist = self._hist.setdefault(u.name, deque(maxlen=self.window))
            d = TopDerived()
            prev = hist[-1] if hist else None
            if prev is not None:
                dt = now - prev.ts
                if dt > 0:
                    if (u.cpu_usage_nsec is not None and prev.cpu_nsec is not None
                            and u.cpu_usage_nsec >= prev.cpu_nsec):
                        d.cpu_pct = (u.cpu_usage_nsec - prev.cpu_nsec) / (dt * 1e9) * 100.0
                    if (u.io_read_bytes is not None and prev.io_read is not None
                            and u.io_read_bytes >= prev.io_read):
                        d.io_read_rate = (u.io_read_bytes - prev.io_read) / dt
                    if (u.io_write_bytes is not None and prev.io_write is not None
                            and u.io_write_bytes >= prev.io_write):
                        d.io_write_rate = (u.io_write_bytes - prev.io_write) / dt
                    if u.memory_anon_bytes is not None and prev.anon is not None:
                        if u.memory_anon_bytes > prev.anon:
                            d.mem_trend = "▲"
                        elif u.memory_anon_bytes < prev.anon:
                            d.mem_trend = "▼"
            hist.append(_Sample(now, u.cpu_usage_nsec, u.memory_anon_bytes,
                                u.io_read_bytes, u.io_write_bytes))
            d.leaking = self._is_leaking(hist)
            derived[u.name] = d
        # Drop history for units that disappeared (avoid unbounded growth).
        for gone in [n for n in self._hist if n not in live_names]:
            del self._hist[gone]
        return derived

    def _is_leaking(self, hist: Deque[_Sample]) -> bool:
        """Suspect a leak when anon memory rises across a full window with at most
        a couple of dips and a meaningful total increase (resets on a real drop)."""
        anon = [s.anon for s in hist if s.anon is not None]
        if len(anon) < self.window:
            return False
        dips = sum(1 for a, b in zip(anon, anon[1:]) if b < a)
        if dips > self.leak_max_dips:
            return False
        growth = anon[-1] - anon[0]
        return (
            growth >= self.leak_min_growth_bytes
            and growth >= anon[0] * self.leak_min_growth_frac
        )

    def net_rate(
        self, system_usage: Optional[SystemResourceUsage], now: float
    ) -> Tuple[Optional[float], Optional[float]]:
        """System-wide (sent_bps, recv_bps) from successive net counter deltas."""
        if not system_usage or system_usage.net_io_sent_bytes is None or system_usage.net_io_recv_bytes is None:
            return None, None
        cur = (now, system_usage.net_io_sent_bytes, system_usage.net_io_recv_bytes)
        prev, self._net_prev = self._net_prev, cur
        if prev is None or (now - prev[0]) <= 0:
            return None, None
        dt = now - prev[0]
        return (cur[1] - prev[1]) / dt, (cur[2] - prev[2]) / dt


def _sort_units(units: List[UnitResourceUsage], sort_key: str) -> List[UnitResourceUsage]:
    if sort_key == "cpu":
        return sorted(units, key=lambda u: u.cpu_usage_nsec or 0, reverse=True)
    if sort_key == "io":
        return sorted(units, key=lambda u: (u.io_read_bytes or 0) + (u.io_write_bytes or 0), reverse=True)
    if sort_key == "limit":
        return sorted(
            units,
            key=lambda u: (u.memory_percent_of_limit or -1.0, u.memory_current_bytes or 0),
            reverse=True,
        )
    return sorted(units, key=lambda u: u.memory_current_bytes or 0, reverse=True)


def _rate_str(bps: Optional[float]) -> str:
    return f"{_format_bytes(int(bps))}/s" if bps is not None else "[dim]—[/dim]"


def build_top_view(
    system_usage: Optional[SystemResourceUsage],
    unit_usages: List[UnitResourceUsage],
    failed_units: Optional[Set[str]] = None,
    sort_key: str = "mem",
    count: int = 25,
    derived: Optional[Dict[str, TopDerived]] = None,
    net_rate: Tuple[Optional[float], Optional[float]] = (None, None),
) -> Group:
    """Render the live view (pure function; unit-testable)."""
    failed_units = failed_units or set()
    derived = derived or {}
    elements: List[Any] = []

    sys_parts = []
    if system_usage:
        if system_usage.cpu_percent is not None:
            sys_parts.append(f"CPU {system_usage.cpu_percent:.0f}%")
        if system_usage.mem_percent is not None:
            sys_parts.append(f"Mem {system_usage.mem_percent:.0f}%")
        if system_usage.swap_percent is not None:
            sys_parts.append(f"Swap {system_usage.swap_percent:.0f}%")
    up, down = net_rate
    if up is not None and down is not None:
        sys_parts.append(f"Net ↑{_format_bytes(int(up))}/s ↓{_format_bytes(int(down))}/s")
    n_leak = sum(1 for d in derived.values() if d.leaking)
    leak_str = f"  ·  [red]leaks?:{n_leak}[/red]" if n_leak else ""
    elements.append(Text.from_markup(
        f"sysdiag top  ·  sort:{sort_key}  ·  {'  '.join(sys_parts)}"
        f"  ·  failed:{len(failed_units)}{leak_str}  ·  (Ctrl-C to quit)"
    ))

    table = Table(show_header=True, header_style="bold cyan", expand=True)
    table.add_column("Unit / Scope", style="cyan", no_wrap=True)
    table.add_column("CPU%", justify="right", width=7)
    table.add_column("Mem", justify="right", width=9)
    table.add_column("Anon", justify="right", width=9)
    table.add_column("Limit", justify="right", width=8)
    table.add_column("%Lim", justify="right", width=5)
    table.add_column("IO R/W", justify="right", width=18)
    table.add_column("Tasks", justify="right", width=5)
    table.add_column("FD", justify="right", width=6)
    table.add_column("Flags", width=8)

    for u in _sort_units(unit_usages, sort_key)[:count]:
        d = derived.get(u.name, TopDerived())
        if u.memory_max_bytes is None:
            limit_str, pct_str = "[dim]none[/dim]", "[dim]—[/dim]"
        else:
            pct = u.memory_percent_of_limit or 0.0
            color = "red" if pct >= 90 else ("yellow" if pct >= 75 else "green")
            limit_str = _format_bytes(u.memory_max_bytes)
            pct_str = f"[{color}]{pct:.0f}%[/{color}]"
        name = f"[red]{u.name}[/red]" if u.name in failed_units else u.name
        anon_str = _format_bytes(u.memory_anon_bytes) if u.memory_anon_bytes is not None else "[dim]—[/dim]"
        if d.mem_trend:
            anon_str += f" {d.mem_trend}"
        flags = "[bold red]LEAK?[/bold red]" if d.leaking else ""
        table.add_row(
            name,
            f"{d.cpu_pct:.1f}" if d.cpu_pct is not None else "[dim]—[/dim]",
            _format_bytes(u.memory_current_bytes),
            anon_str,
            limit_str,
            pct_str,
            f"{_rate_str(d.io_read_rate)}/{_rate_str(d.io_write_rate)}",
            str(u.tasks_current) if u.tasks_current is not None else "[dim]—[/dim]",
            str(d.fd_count) if d.fd_count is not None else "[dim]—[/dim]",
            flags,
        )
    elements.append(table)
    return Group(*elements)


def run_top(
    app_config: Dict[str, Any],
    interval: float = 2.0,
    sort_key: str = "mem",
    count: int = 25,
    console: Optional[Console] = None,
) -> None:
    """Run the live refresh loop until interrupted (Ctrl-C)."""
    from .modules import health as health_mod
    from .modules import resources as res_mod

    console = console or Console()
    if sort_key not in SORT_KEYS:
        sort_key = "mem"

    manager = health_mod._get_systemd_manager_interface() if health_mod.HAS_DBUS else None

    def fetch_units():
        if manager is not None:
            units, _ = health_mod._get_all_units_dbus(manager)
            if units:
                return units
        units, _ = health_mod._get_all_units_json()
        return units or []

    units = fetch_units()
    path_cache: Dict[str, Optional[str]] = {}
    state = TopState()
    tick = 0
    # The analyzers emit log records every refresh; on a full-screen Live view
    # those flash over the display. Silence logging for the loop, restore after.
    logging.disable(logging.ERROR)
    try:
        with Live(console=console, screen=True, refresh_per_second=4) as live:
            while True:
                if tick and tick % _UNIT_REFRESH_EVERY == 0:
                    units = fetch_units()
                    path_cache.clear()
                system_usage = res_mod.get_system_wide_usage()
                unit_usages = res_mod.get_unit_resource_usage(
                    units, manager, cgroup_path_cache=path_cache
                )
                now = time.monotonic()
                derived = state.update(unit_usages, now)
                net = state.net_rate(system_usage, now)
                # FD counting is per-PID /proc work, so only do it for the units
                # actually displayed (the sorted top-N).
                for u in _sort_units(unit_usages, sort_key)[:count]:
                    if u.cgroup_path:
                        derived[u.name].fd_count = res_mod.get_cgroup_fd_count(u.cgroup_path)
                failed = {u.name for u in units if u.active_state == "failed"}
                live.update(
                    build_top_view(system_usage, unit_usages, failed, sort_key, count, derived, net)
                )
                time.sleep(interval)
                tick += 1
    except KeyboardInterrupt:
        pass
    finally:
        logging.disable(logging.NOTSET)
