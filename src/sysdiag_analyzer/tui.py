# src/sysdiag_analyzer/tui.py
"""A live, top-like view of per-unit cgroup resource usage.

Built on rich.Live (no extra dependencies). The expensive DBus cgroup-path
lookup is resolved once and cached, so each refresh only re-reads the cheap
/sys/fs/cgroup files; the unit list is refreshed periodically.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Set

from rich.console import Console, Group
from rich.live import Live
from rich.table import Table
from rich.text import Text

from .datatypes import SystemResourceUsage, UnitResourceUsage
from .output import _format_bytes, _format_nanoseconds

SORT_KEYS = ("mem", "cpu", "limit", "io")
# How often (in refresh ticks) to re-fetch the unit list to catch new/gone units.
_UNIT_REFRESH_EVERY = 10


def _sort_units(units: List[UnitResourceUsage], sort_key: str) -> List[UnitResourceUsage]:
    if sort_key == "cpu":
        return sorted(units, key=lambda u: u.cpu_usage_nsec or 0, reverse=True)
    if sort_key == "io":
        return sorted(units, key=lambda u: (u.io_read_bytes or 0) + (u.io_write_bytes or 0), reverse=True)
    if sort_key == "limit":
        # Highest %-of-limit first; units with no limit (None) sort last.
        return sorted(
            units,
            key=lambda u: (u.memory_percent_of_limit or -1.0, u.memory_current_bytes or 0),
            reverse=True,
        )
    return sorted(units, key=lambda u: u.memory_current_bytes or 0, reverse=True)


def build_top_view(
    system_usage: Optional[SystemResourceUsage],
    unit_usages: List[UnitResourceUsage],
    failed_units: Optional[Set[str]] = None,
    sort_key: str = "mem",
    count: int = 25,
) -> Group:
    """Render the live view as a rich renderable (pure function; unit-testable)."""
    failed_units = failed_units or set()
    elements: List[Any] = []

    sys_parts = []
    if system_usage:
        if system_usage.cpu_percent is not None:
            sys_parts.append(f"CPU {system_usage.cpu_percent:.0f}%")
        if system_usage.mem_percent is not None:
            sys_parts.append(f"Mem {system_usage.mem_percent:.0f}%")
        if system_usage.swap_percent is not None:
            sys_parts.append(f"Swap {system_usage.swap_percent:.0f}%")
    header = (
        f"sysdiag top  ·  sort:{sort_key}  ·  {'  '.join(sys_parts)}"
        f"  ·  failed:{len(failed_units)}  ·  (Ctrl-C to quit)"
    )
    elements.append(Text(header, style="bold"))

    table = Table(show_header=True, header_style="bold cyan", expand=True)
    table.add_column("Unit / Scope", style="cyan", no_wrap=True)
    table.add_column("Mem", justify="right", width=10)
    table.add_column("Limit", justify="right", width=10)
    table.add_column("%Lim", justify="right", width=6)
    table.add_column("CPU (cum)", justify="right", width=11)
    table.add_column("IO R/W", justify="right", width=16)
    table.add_column("Tasks", justify="right", width=6)

    for u in _sort_units(unit_usages, sort_key)[:count]:
        if u.memory_max_bytes is None:
            limit_str, pct_str = "[dim]none[/dim]", "[dim]—[/dim]"
        else:
            pct = u.memory_percent_of_limit or 0.0
            color = "red" if pct >= 90 else ("yellow" if pct >= 75 else "green")
            limit_str = _format_bytes(u.memory_max_bytes)
            pct_str = f"[{color}]{pct:.0f}%[/{color}]"
        name = f"[red]{u.name}[/red]" if u.name in failed_units else u.name
        io_str = f"{_format_bytes(u.io_read_bytes)}/{_format_bytes(u.io_write_bytes)}"
        table.add_row(
            name,
            _format_bytes(u.memory_current_bytes),
            limit_str,
            pct_str,
            _format_nanoseconds(u.cpu_usage_nsec),
            io_str,
            str(u.tasks_current) if u.tasks_current is not None else "[dim]—[/dim]",
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
    tick = 0
    try:
        with Live(console=console, screen=True, refresh_per_second=4) as live:
            while True:
                if tick and tick % _UNIT_REFRESH_EVERY == 0:
                    units = fetch_units()
                    path_cache.clear()  # units may have changed; re-resolve paths
                system_usage = res_mod.get_system_wide_usage()
                unit_usages = res_mod.get_unit_resource_usage(
                    units, manager, cgroup_path_cache=path_cache
                )
                failed = {u.name for u in units if u.active_state == "failed"}
                live.update(build_top_view(system_usage, unit_usages, failed, sort_key, count))
                time.sleep(interval)
                tick += 1
    except KeyboardInterrupt:
        pass
