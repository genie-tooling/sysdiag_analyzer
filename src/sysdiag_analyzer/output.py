# src/sysdiag_analyzer/output.py
# -*- coding: utf-8 -*-

import datetime
import json
import logging
import psutil
from dataclasses import asdict
from typing import Any, List, Optional

try:
    from pygments.util import ClassNotFound
except ImportError:
    ClassNotFound = Exception  # Fallback if pygments isn't installed

from rich.console import Console, Group
from rich.markdown import Markdown
from rich.padding import Padding
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from .datatypes import (
    BootAnalysisResult,
    DependencyAnalysisResult,
    EBPFAnalysisResult,
    FullDependencyAnalysisResult,
    HealthAnalysisResult,
    LLMAnalysisResult,
    LogAnalysisResult,
    MLAnalysisResult,
    ResourceAnalysisResult,
    SystemReport,
    SingleUnitReport,
    FailedUnitDependencyInfo,
)

log = logging.getLogger(__name__)

# --- Constants ---
MAX_EXAMPLE_MESSAGES: int = 3
MAX_CYCLES_TO_SHOW: int = 20
MAX_EBPF_EVENTS_TO_SHOW: int = 20


# --- Helper Functions ---
def _format_bytes(byte_count: Optional[int]) -> str:
    """Formats bytes into human-readable format (KiB, MiB, GiB)."""
    if byte_count is None:
        return "[dim]n/a[/dim]"
    if byte_count < 1024:
        return f"{byte_count} B"
    elif byte_count < 1024**2:
        return f"{byte_count / 1024:.1f} KiB"
    elif byte_count < 1024**3:
        return f"{byte_count / (1024**2):.1f} MiB"
    else:
        return f"{byte_count / (1024**3):.1f} GiB"


def _format_nanoseconds(nsec_count: Optional[int]) -> str:
    """Formats nanoseconds into human-readable seconds or milliseconds."""
    if nsec_count is None:
        return "[dim]n/a[/dim]"
    sec = nsec_count / 1_000_000_000
    if sec >= 1.0:
        return f"{sec:.2f} s"
    else:
        msec = sec * 1000
        return f"{msec:.1f} ms"


def _format_seconds(sec_count: Optional[float]) -> str:
    """Formats seconds into a human-readable string (s, m, h)."""
    if sec_count is None:
        return "[dim]n/a[/dim]"
    if sec_count < 60.0:
        return f"{sec_count:.2f}s"
    minutes = sec_count / 60.0
    if minutes < 60.0:
        return f"{minutes:.1f}m"
    hours = minutes / 60.0
    return f"{hours:.1f}h"


def _format_log_snippet(logs: List[str], max_lines: int = 3) -> Any:
    """
    Formats a log snippet, returning the most appropriate Rich renderable
    (Text, Syntax, or Group).
    """
    if not logs:
        return Text("[dim](No logs available)[/dim]")
    if len(logs) == 1 and logs[0].startswith("[Error fetching logs:"):
        return Text(f"[red]{logs[0]}[/red]")

    display_logs = logs[-max_lines:]
    num_omitted = len(logs) - len(display_logs)
    log_content = "\n".join(display_logs)

    renderable_parts = []

    if num_omitted > 0:
        header = Text(f"[dim]... ({num_omitted} older lines omitted) ...[/dim]\n")
        renderable_parts.append(header)

    lexer = "log" if any(c in log_content for c in "[]:=") else "text"
    try:
        syntax_block = Syntax(
            log_content, lexer, theme="default", line_numbers=False, word_wrap=True
        )
        renderable_parts.append(syntax_block)
    except ClassNotFound:
        log.warning(
            f"Pygments lexer '{lexer}' not found (is 'pygments' installed?). Falling back to plain text."
        )
        renderable_parts.append(Text(log_content))
    except Exception:
        log.warning(
            f"Syntax highlighting failed for lexer '{lexer}'. Falling back to plain text."
        )
        renderable_parts.append(Text(log_content))

    if not renderable_parts:
        return Text("")
    elif len(renderable_parts) == 1:
        return renderable_parts[0]
    else:
        return Group(*renderable_parts)


# --- Analysis Section Formatting ---
def format_boot_report(result: Optional[BootAnalysisResult], console: Console) -> None:
    """Formats and prints the Boot Analysis results using Rich."""
    log.debug(f"format_boot_report called with result object: {result is not None}")
    if not result:
        console.print(
            Panel(
                "[yellow]Boot analysis data is not available.[/yellow]",
                title="Boot Analysis",
                border_style="dim",
            )
        )
        return

    content_parts: List[Any] = []

    if result.times:
        if result.times.error:
            content_parts.append(f"[dim]Times:[/dim] [red]Error: {result.times.error}[/red]")
        else:
            times_str_parts = []
            if result.times.firmware:
                times_str_parts.append(f"Firmware: [bold]{result.times.firmware}[/bold]")
            if result.times.loader:
                times_str_parts.append(f"Loader: [bold]{result.times.loader}[/bold]")
            if result.times.kernel:
                times_str_parts.append(f"Kernel: [bold]{result.times.kernel}[/bold]")
            if result.times.initrd:
                times_str_parts.append(f"Initrd: [bold]{result.times.initrd}[/bold]")
            if result.times.userspace:
                times_str_parts.append(f"Userspace: [bold]{result.times.userspace}[/bold]")
            if result.times.total:
                times_str_parts.append(f"Total: [bold]{result.times.total}[/bold]")
            times_str = " + ".join(
                p
                for p in times_str_parts
                if ": [bold]None[/bold]" not in p and ": [bold][/bold]" not in p
            )
            if times_str:
                content_parts.append(f"[dim]Times:[/dim] {times_str}")
            else:
                content_parts.append(
                    "[dim]Times:[/dim] [yellow]No specific timing data parsed.[/yellow]"
                )
    else:
        content_parts.append("[dim]Times:[/dim] [yellow]Timing data unavailable.[/yellow]")

    if content_parts:
        content_parts.append("")
    if result.blame_error:
        content_parts.append(
            f"[dim]Blame (Journal):[/dim] [red]Error: {result.blame_error}[/red]"
        )
    elif result.blame:
        table = Table(
            title="Unit Activation Times (Journal Analysis - Top 20)",
            show_header=True,
            header_style="bold magenta",
            expand=True,
        )
        table.add_column("Time", style="dim", width=10, no_wrap=True)
        table.add_column("Unit", style="cyan")
        limit = 20
        for i, item in enumerate(result.blame):
            if i >= limit:
                table.add_row("...", f"({len(result.blame) - limit} more)")
                break
            table.add_row(item.time, item.unit)
        content_parts.append(table)
    else:
        content_parts.append(
            "[dim]Blame (Journal):[/dim] [yellow]No unit timing data found or parsed from journal.[/yellow]"
        )

    if content_parts:
        content_parts.append("")
    if result.critical_chain_error:
        content_parts.append(
            f"[dim]Critical Chain:[/dim] [red]Error: {result.critical_chain_error}[/red]"
        )
    elif result.critical_chain:
        chain_text = Text()
        chain_text.append(
            "Critical Chain (systemd-analyze critical-chain):\n", style="bold magenta"
        )
        for item in result.critical_chain:
            indent = " " * item.indent
            time_at = f" {item.time_at}" if item.time_at else ""
            time_delta_str = ""
            if item.time_delta:
                try:
                    delta_val_str = item.time_delta.lstrip("+")
                    time_val = 0.0
                    if delta_val_str.endswith("ms"):
                        time_val = float(delta_val_str.rstrip("ms"))
                        time_val /= 1000.0
                    elif delta_val_str.endswith("s"):
                        time_val = float(delta_val_str.rstrip("s"))
                    else:
                        time_val = float(delta_val_str)
                    if time_val > 1.0:
                        time_delta_str = f" [bold red]{item.time_delta}[/bold red]"
                    elif time_val > 0.5:
                        time_delta_str = f" [red]{item.time_delta}[/red]"
                    else:
                        time_delta_str = f" [yellow]{item.time_delta}[/yellow]"
                except ValueError:
                    time_delta_str = f" [yellow]{item.time_delta}[/yellow]"
            chain_text.append(f"{indent}{item.unit}{time_at}{time_delta_str}\n")
        content_parts.append(chain_text)
    else:
        content_parts.append(
            "[dim]Critical Chain:[/dim] [yellow]No critical chain data found or parsed.[/yellow]"
        )

    renderable_parts = [part for part in content_parts if part]
    if renderable_parts:
        console.print(
            Panel(
                Group(*renderable_parts),
                title="Boot Analysis",
                border_style="blue",
                expand=False,
            )
        )
    else:
        log.warning("format_boot_report generated empty content, panel not printed.")


def format_health_report(
    result: Optional[HealthAnalysisResult], console: Console
) -> None:
    """Formats and prints the Service Health Analysis results using Rich."""
    log.debug(f"format_health_report called with result object: {result is not None}")
    if not result:
        console.print(
            Panel(
                "[yellow]Health analysis data is not available.[/yellow]",
                title="Service Health Analysis",
                border_style="dim",
            )
        )
        return

    output_elements: List[Any] = []
    if result.analysis_error:
        console.print(
            Panel(
                f"[red]Error during analysis: {result.analysis_error}[/red]",
                title="Service Health Analysis Error",
                border_style="red",
                expand=False,
            )
        )
        return

    if result.failed_units:
        table = Table(
            title=f"Failed Units ({len(result.failed_units)})",
            show_header=True,
            header_style="bold red",
            expand=True,
        )
        table.add_column("Unit", style="red", no_wrap=True)
        table.add_column("Load", style="dim", width=8)
        table.add_column("Active", style="dim", width=8)
        table.add_column("Sub", style="dim", width=10)
        table.add_column("Details / Result", width=20)
        table.add_column("Recent Logs")
        for unit in result.failed_units:
            details_str_parts = []
            if unit.details:
                res = unit.details.get("Result")
                ex_code = unit.details.get("ExecMainStatus")
                ex_stat = unit.details.get("ExecMainCode")
                pid = unit.details.get("ExecMainPID")
                if res and res != "success":
                    details_str_parts.append(f"Result: {res}")
                if ex_code is not None:
                    details_str_parts.append(f"ExitCode: {ex_code}")
                if ex_stat is not None:
                    details_str_parts.append(f"ExitStatus: {ex_stat}")
                if pid is not None and pid != 0:
                    details_str_parts.append(f"PID: {pid}")
            details_str = " ".join(details_str_parts)
            if unit.error_message and not details_str:
                details_str = f"[dim]({unit.error_message})[/dim]"
            table.add_row(
                unit.name,
                unit.load_state or "n/a",
                unit.active_state or "n/a",
                unit.sub_state or "n/a",
                details_str.strip() or "[dim]n/a[/dim]",
                _format_log_snippet(unit.recent_logs),
            )
        output_elements.append(table)

    if result.flapping_units:
        table = Table(
            title=f"Potentially Flapping Units ({len(result.flapping_units)})",
            show_header=True,
            header_style="bold yellow",
            expand=True,
        )
        table.add_column("Unit", style="yellow", no_wrap=True)
        table.add_column("Restarts", style="magenta", width=8)
        table.add_column("State (Load/Active/Sub)", width=25)
        table.add_column("Recent Logs")
        for unit in result.flapping_units:
            restarts = unit.details.get("NRestarts", "?")
            state_str = (
                f"{unit.load_state or '?'}/{unit.active_state or '?'}/{unit.sub_state or '?'}"
            )
            table.add_row(
                unit.name, str(restarts), state_str, _format_log_snippet(unit.recent_logs)
            )
        output_elements.append(table)

    if result.problematic_sockets:
        table = Table(
            title=f"Problematic Sockets ({len(result.problematic_sockets)})",
            show_header=True,
            header_style="bold orange1",
            expand=True,
        )
        table.add_column("Socket Unit", style="orange1", no_wrap=True)
        table.add_column("State (Load/Active/Sub)", width=25)
        table.add_column("Issue", style="red")
        table.add_column("Recent Logs")
        for unit in result.problematic_sockets:
            state_str = (
                f"{unit.load_state or '?'}/{unit.active_state or '?'}/{unit.sub_state or '?'}"
            )
            issue = unit.error_message or "Unknown issue"
            table.add_row(
                unit.name, state_str, issue, _format_log_snippet(unit.recent_logs)
            )
        output_elements.append(table)

    if result.problematic_timers:
        table = Table(
            title=f"Problematic Timers ({len(result.problematic_timers)})",
            show_header=True,
            header_style="bold cyan",
            expand=True,
        )
        table.add_column("Timer Unit", style="cyan", no_wrap=True)
        table.add_column("State (Load/Active/Sub)", width=25)
        table.add_column("Issue", style="red")
        table.add_column("Last Triggered", width=20)
        table.add_column("Recent Logs")
        for unit in result.problematic_timers:
            state_str = (
                f"{unit.load_state or '?'}/{unit.active_state or '?'}/{unit.sub_state or '?'}"
            )
            issue = unit.error_message or "Unknown issue"
            last_trigger_str = "[dim]n/a[/dim]"
            ts_usec = unit.details.get("LastTriggerUSec")
            if ts_usec:
                try:
                    ts_usec_int = int(ts_usec)
                    if ts_usec_int == 0:
                        last_trigger_str = "[dim]Never[/dim]"
                    else:
                        dt_object = datetime.datetime.fromtimestamp(
                            ts_usec_int / 1_000_000, tz=datetime.timezone.utc
                        )
                        last_trigger_str = dt_object.strftime("%Y-%m-%d %H:%M:%S %Z")
                except (ValueError, TypeError, OverflowError):
                    last_trigger_str = str(ts_usec)
            table.add_row(
                unit.name,
                state_str,
                issue,
                last_trigger_str,
                _format_log_snippet(unit.recent_logs),
            )
        output_elements.append(table)

    summary_message = None
    if (
        not result.failed_units
        and not result.flapping_units
        and not result.problematic_sockets
        and not result.problematic_timers
    ):
        summary_message = Panel(
            f"[green]No failed, flapping, or problematic socket/timer units detected among {result.all_units_count} units analyzed.[/green]",
            title="Service Health Analysis Summary",
            border_style="green",
            expand=False,
        )
    elif not output_elements:
        summary_message = Panel(
            f"[dim]No specific health issues identified among {result.all_units_count} units analyzed.[/dim]",
            title="Service Health Analysis Summary",
            border_style="dim",
            expand=False,
        )

    if output_elements:
        console.print(Padding(f"Analyzed {result.all_units_count} units.", (0, 0, 1, 0)))
        for element in output_elements:
            console.print(element)
    elif summary_message:
        console.print(summary_message)
    else:
        log.warning("format_health_report generated no output elements.")


def format_resource_report(
    result: Optional[ResourceAnalysisResult], console: Console
) -> None:
    """Formats and prints the Resource Analysis results using Rich."""
    log.debug(f"format_resource_report called with result object: {result is not None}")
    if not result:
        console.print(
            Panel(
                "[yellow]Resource analysis data is not available.[/yellow]",
                title="Resource Analysis",
                border_style="dim",
            )
        )
        return

    output_elements: List[Any] = []
    title = "Resource Analysis"
    border_style = "yellow"

    if result.analysis_error:
        output_elements.append(f"[red]Analysis Error: {result.analysis_error}[/red]")
        border_style = "red"

    if result.system_usage:
        sys_usage = result.system_usage
        if sys_usage.error:
            output_elements.append(f"[red]System Usage Error: {sys_usage.error}[/red]")
        else:
            sys_lines = []
            if sys_usage.cpu_percent is not None:
                sys_lines.append(
                    f"  CPU Usage: [bold cyan]{sys_usage.cpu_percent:.1f}%[/bold cyan]"
                )
            if (
                sys_usage.mem_percent is not None
                and sys_usage.mem_available_bytes is not None
                and sys_usage.mem_total_bytes is not None
            ):
                sys_lines.append(
                    f"  Memory:    [bold magenta]{sys_usage.mem_percent:.1f}%[/bold magenta] used ([cyan]{_format_bytes(sys_usage.mem_available_bytes)}[/cyan] available / [dim]{_format_bytes(sys_usage.mem_total_bytes)} total[/dim])"
                )
            if (
                sys_usage.swap_percent is not None
                and sys_usage.swap_used_bytes is not None
                and sys_usage.swap_total_bytes is not None
            ):
                if sys_usage.swap_total_bytes > 0:
                    sys_lines.append(
                        f"  Swap:      [bold yellow]{sys_usage.swap_percent:.1f}%[/bold yellow] used ([cyan]{_format_bytes(sys_usage.swap_total_bytes - sys_usage.swap_used_bytes)}[/cyan] free / [dim]{_format_bytes(sys_usage.swap_total_bytes)} total[/dim])"
                    )
            if sys_lines:
                output_elements.append("[bold green]System-Wide Usage:[/bold green]")
                output_elements.extend(sys_lines)
            else:
                output_elements.append(
                    "[yellow]System-wide usage data unavailable.[/yellow]"
                )
    else:
        output_elements.append("[yellow]System-wide usage data unavailable.[/yellow]")

    has_unit_data = (
        result.top_cpu_units or result.top_memory_units or result.top_io_units
    )
    has_child_data = result.child_process_groups
    if output_elements and (has_unit_data or has_child_data):
        output_elements.append("")

    if result.top_cpu_units:
        table = Table(
            title=f"Top {len(result.top_cpu_units)} CPU Consumers (systemd Units - cgroup)",
            show_header=True,
            header_style="bold cyan",
            expand=True,
        )
        table.add_column("Unit", style="cyan", no_wrap=True)
        table.add_column("CPU Time", style="magenta", width=12, justify="right")
        table.add_column("Current Mem", style="blue", width=12, justify="right")
        table.add_column("Tasks", style="green", width=7, justify="right")
        table.add_column("Error", style="red")
        for unit in result.top_cpu_units:
            table.add_row(
                unit.name,
                _format_nanoseconds(unit.cpu_usage_nsec),
                _format_bytes(unit.memory_current_bytes),
                str(unit.tasks_current)
                if unit.tasks_current is not None
                else "[dim]n/a[/dim]",
                unit.error or "",
            )
        output_elements.append(table)
    if result.top_memory_units:
        table = Table(
            title=f"Top {len(result.top_memory_units)} Memory Consumers (systemd Units - cgroup)",
            show_header=True,
            header_style="bold magenta",
            expand=True,
        )
        table.add_column("Unit", style="magenta", no_wrap=True)
        table.add_column("Current Mem", style="blue", width=12, justify="right")
        table.add_column("Peak Mem", style="cyan", width=12, justify="right")
        table.add_column("CPU Time", style="magenta", width=12, justify="right")
        table.add_column("Tasks", style="green", width=7, justify="right")
        table.add_column("Error", style="red")
        for unit in result.top_memory_units:
            table.add_row(
                unit.name,
                _format_bytes(unit.memory_current_bytes),
                _format_bytes(unit.memory_peak_bytes),
                _format_nanoseconds(unit.cpu_usage_nsec),
                str(unit.tasks_current)
                if unit.tasks_current is not None
                else "[dim]n/a[/dim]",
                unit.error or "",
            )
        output_elements.append(table)
    if result.top_io_units:
        table = Table(
            title=f"Top {len(result.top_io_units)} I/O Consumers (systemd Units - cgroup - Cumulative)",
            show_header=True,
            header_style="bold yellow",
            expand=True,
        )
        table.add_column("Unit", style="yellow", no_wrap=True)
        table.add_column("Read Bytes", style="blue", width=12, justify="right")
        table.add_column("Write Bytes", style="cyan", width=12, justify="right")
        table.add_column("Total I/O", style="green", width=12, justify="right")
        table.add_column("Error", style="red")
        for unit in result.top_io_units:
            total_io = (unit.io_read_bytes or 0) + (unit.io_write_bytes or 0)
            table.add_row(
                unit.name,
                _format_bytes(unit.io_read_bytes),
                _format_bytes(unit.io_write_bytes),
                _format_bytes(total_io) if total_io > 0 else "[dim]n/a[/dim]",
                unit.error or "",
            )
        output_elements.append(table)

    if result.child_process_groups:
        table = Table(
            title=f"Child Process Group Usage ({len(result.child_process_groups)} groups - psutil)",
            show_header=True,
            header_style="bold blue",
            expand=True,
        )
        table.add_column("Command Name", style="cyan", no_wrap=True)
        table.add_column("Parent Unit", style="blue", no_wrap=True)
        table.add_column("Process Count", style="green", width=8, justify="right")
        table.add_column("Aggr. CPU Time", style="magenta", width=12, justify="right")
        table.add_column("Aggr. Memory", style="yellow", width=14, justify="right")
        table.add_column("Example PIDs", style="dim")
        for group in result.child_process_groups:
            cpu_str = _format_seconds(group.aggregated_cpu_seconds_total)
            mem_str = _format_bytes(group.aggregated_memory_bytes)
            pids_str = ", ".join(map(str, group.pids))
            if len(group.pids) < group.process_count:
                pids_str += "..."
            table.add_row(
                group.command_name,
                group.parent_unit,
                str(group.process_count),
                cpu_str,
                mem_str,
                pids_str,
            )
        output_elements.append(table)

    if output_elements:
        final_panel = Panel(
            Group(*output_elements), title=title, border_style=border_style, expand=False
        )
        console.print(final_panel)
    elif not result.analysis_error:
        console.print(
            Panel("[dim]No resource usage data to display.[/dim]", title=title, border_style="dim")
        )


def format_log_report(result: Optional[LogAnalysisResult], console: Console) -> None:
    """Formats and prints the Log Analysis results using Rich."""
    log.debug(f"format_log_report called with result object: {result is not None}")
    if not result:
        console.print(
            Panel(
                "[yellow]Log analysis data is not available.[/yellow]",
                title="Log Analysis",
                border_style="dim",
            )
        )
        return

    output_elements: List[Any] = []
    title = "Log Analysis"
    border_style = "magenta"
    if result.analysis_error:
        output_elements.append(f"[red]Analysis Error: {result.analysis_error}[/red]")
        border_style = "red"
    source_info = f"Source: {result.log_source or 'unknown'}"
    count_info = f"Entries Analyzed: {result.total_entries_analyzed}"
    output_elements.append(f"[dim]{source_info} | {count_info}[/dim]")
    oom_events = [p for p in result.detected_patterns if p.pattern_type == "OOM"]
    error_patterns = sorted(
        [p for p in result.detected_patterns if p.pattern_type == "Error"],
        key=lambda p: p.count,
        reverse=True,
    )
    warning_patterns = sorted(
        [p for p in result.detected_patterns if p.pattern_type == "Warning"],
        key=lambda p: p.count,
        reverse=True,
    )
    if (
        not oom_events
        and not error_patterns
        and not warning_patterns
        and not result.analysis_error
    ):
        output_elements.append(
            "\n[green]No significant OOM, error, or warning patterns detected.[/green]"
        )
    else:
        output_elements.append("")
    if oom_events:
        oom_info = oom_events[0]
        table = Table(
            title=f"[bold red]OOM Killer Events Detected ({oom_info.count})[/bold red]",
            show_header=True,
            header_style="bold red",
            expand=True,
        )
        table.add_column("Count", style="red", width=8, justify="right")
        table.add_column("Example Messages")
        table.add_row(
            str(oom_info.count),
            _format_log_snippet(oom_info.example_messages, max_lines=MAX_EXAMPLE_MESSAGES),
        )
        output_elements.append(table)
    if error_patterns:
        table = Table(
            title=f"Top Error Patterns ({len(error_patterns)})",
            show_header=True,
            header_style="bold yellow",
            expand=True,
        )
        table.add_column("Pattern Key", style="yellow", no_wrap=True, width=20)
        table.add_column("Count", style="magenta", width=8, justify="right")
        table.add_column("Level", style="dim", width=8)
        table.add_column("Example Messages")
        for pattern in error_patterns:
            table.add_row(
                pattern.pattern_key,
                str(pattern.count),
                pattern.level or "[dim]n/a[/dim]",
                _format_log_snippet(
                    pattern.example_messages, max_lines=MAX_EXAMPLE_MESSAGES
                ),
            )
        output_elements.append(table)
    if warning_patterns:
        table = Table(
            title=f"Top Warning Patterns ({len(warning_patterns)})",
            show_header=True,
            header_style="bold cyan",
            expand=True,
        )
        table.add_column("Pattern Key", style="cyan", no_wrap=True, width=20)
        table.add_column("Count", style="magenta", width=8, justify="right")
        table.add_column("Level", style="dim", width=8)
        table.add_column("Example Messages")
        for pattern in warning_patterns:
            table.add_row(
                pattern.pattern_key,
                str(pattern.count),
                pattern.level or "[dim]n/a[/dim]",
                _format_log_snippet(
                    pattern.example_messages, max_lines=MAX_EXAMPLE_MESSAGES
                ),
            )
        output_elements.append(table)
    if output_elements:
        final_panel = Panel(
            Group(*output_elements), title=title, border_style=border_style, expand=False
        )
        console.print(final_panel)
    elif not result.analysis_error:
        console.print(
            Panel(
                "[dim]No log analysis data to display.[/dim]",
                title=title,
                border_style="dim",
            )
        )


def _format_dependency_table(unit_info: FailedUnitDependencyInfo) -> Optional[Table]:
    """Helper to create a Rich Table for a unit's dependencies."""
    if not unit_info.dependencies:
        return None

    table = Table(
        show_header=True,
        header_style="bold blue",
        expand=False,
        box=None,
        padding=(0, 1),
    )
    table.add_column("Dependency", style="cyan", no_wrap=True, min_width=20)
    table.add_column("Type", style="magenta", width=10)
    table.add_column("State (L / A / S)", style="white", width=25)
    table.add_column("Problematic?", style="yellow", width=12, justify="center")

    for dep in unit_info.dependencies:
        state_str = f"{dep.current_load_state or '?'} / {dep.current_active_state or '?'} / {dep.current_sub_state or '?'}"
        if dep.current_active_state == "failed":
            state_str = f"[red]{state_str}[/red]"
        elif dep.current_active_state == "inactive":
            state_str = f"[dim]{state_str}[/dim]"
        problem_str = "[bold red]YES[/bold red]" if dep.is_problematic else "[dim]No[/dim]"
        table.add_row(dep.name, dep.type, state_str, problem_str)
    return table


def format_dependency_report(
    result: Optional[DependencyAnalysisResult], console: Console
) -> None:
    """Formats and prints the Dependency Analysis results using Rich."""
    log.debug(f"format_dependency_report called with result object: {result is not None}")
    title = "Dependency Analysis for Failed Units"
    border_style = "cyan"

    if not result:
        console.print(
            Panel(
                "[yellow]Dependency analysis data is not available.[/yellow]",
                title=title,
                border_style="dim",
            )
        )
        return

    if result.analysis_error:
        console.print(
            Panel(
                f"[red]Overall Analysis Error: {result.analysis_error}[/red]",
                title=title,
                border_style="red",
                expand=False,
            )
        )
        return

    if not result.failed_unit_dependencies:
        console.print(
            Panel(
                "[dim]No failed units found or analyzed for dependencies.[/dim]",
                title=title,
                border_style="dim",
                expand=False,
            )
        )
        return

    console.print(
        Panel(
            f"[bold]Analysis for {len(result.failed_unit_dependencies)} Failed Unit(s)[/bold]",
            title=title,
            border_style=border_style,
            expand=False,
        )
    )
    for unit_info in result.failed_unit_dependencies:
        unit_content: List[Any] = []
        if unit_info.error:
            unit_content.append(
                f"  [red]Error analyzing dependencies: {unit_info.error}[/red]"
            )

        dep_table = _format_dependency_table(unit_info)
        if dep_table:
            unit_content.append(dep_table)
        elif not unit_info.error:
            unit_content.append("  [dim]No dependencies listed or analyzed.[/dim]")

        console.print(
            Panel(
                Padding(Group(*unit_content), (0, 1)),
                title=f"Failed Unit: [white]{unit_info.unit_name}[/white]",
                border_style="yellow",
                expand=False,
            )
        )


def format_full_dependency_report(
    result: Optional[FullDependencyAnalysisResult], console: Console
) -> None:
    """Formats and prints the Full Dependency Graph Analysis results."""
    log.debug(
        f"format_full_dependency_report called with result object: {result is not None}"
    )
    title = "Full Dependency Graph Analysis"
    border_style = "blue"

    if not result:
        log.debug("Skipping full dependency report formatting (no result data).")
        return

    output_elements = []
    if result.analysis_error:
        output_elements.append(f"[red]Analysis Error: {result.analysis_error}[/red]")
        border_style = "red"
    if result.dependency_fetch_error:
        output_elements.append(
            f"  [dim]Fetch Error:[/dim] [red]{result.dependency_fetch_error}[/red]"
        )
    if result.graph_build_error:
        output_elements.append(
            f"  [dim]Graph Build Error:[/dim] [red]{result.graph_build_error}[/red]"
        )
    if not result.detected_cycles:
        if not result.analysis_error:
            output_elements.append("[green]No dependency cycles detected.[/green]")
    else:
        if result.analysis_error:
            output_elements.append("")
        output_elements.append(
            f"[bold yellow]Detected {len(result.detected_cycles)} Dependency Cycles:[/bold yellow]"
        )
        cycle_text = Text()
        for i, cycle in enumerate(result.detected_cycles):
            if i >= MAX_CYCLES_TO_SHOW:
                cycle_text.append(
                    f"\n... ({len(result.detected_cycles) - MAX_CYCLES_TO_SHOW} more cycles omitted) ..."
                )
                break
            cycle_str = " -> ".join(cycle) + f" -> {cycle[0]}"
            cycle_text.append(f"  {i+1}. {cycle_str}\n")
        output_elements.append(cycle_text)
    final_content = "\n".join(str(el) for el in output_elements).strip()
    if final_content:
        console.print(
            Panel(final_content, title=title, border_style=border_style, expand=False)
        )


def format_ml_report(result: Optional[MLAnalysisResult], console: Console) -> None:
    """Formats and prints the ML Analysis results using Rich."""
    log.debug(f"format_ml_report called with result object: {result is not None}")
    title = "ML Anomaly Detection Analysis"
    border_style = "purple"
    if not result:
        log.debug("Skipping ML report formatting (no result data).")
        return
    output_elements: List[Any] = []
    if result.error:
        output_elements.append(f"[red]Analysis Error: {result.error}[/red]")
        border_style = "red"
    models_info = f"Models Loaded: {result.models_loaded_count}"
    units_info = f"Units Analyzed: {result.units_analyzed_count}"
    output_elements.append(f"[dim]{models_info} | {units_info}[/dim]")
    if result.skipped_zero_variance_units:
        skipped_count = len(result.skipped_zero_variance_units)
        skipped_examples = ", ".join(result.skipped_zero_variance_units[:5])
        if skipped_count > 5:
            skipped_examples += "..."
        output_elements.append(
            f"[dim]Skipped {skipped_count} units during training (zero variance): {skipped_examples}[/dim]"
        )
    if not result.anomalies_detected:
        if not result.error:
            output_elements.append(
                "\n[green]No anomalies detected based on historical data.[/green]"
            )
    else:
        if result.error or result.skipped_zero_variance_units:
            output_elements.append("")
        sorted_anomalies = sorted(result.anomalies_detected, key=lambda a: a.score)
        table = Table(
            title=f"[bold yellow]Detected Anomalies ({len(result.anomalies_detected)})[/bold yellow]",
            show_header=True,
            header_style="bold yellow",
            expand=True,
        )
        table.add_column("Unit", style="yellow", no_wrap=True)
        table.add_column("Anomaly Score", style="magenta", width=15, justify="right")
        for anomaly in sorted_anomalies:
            score_str = f"{anomaly.score:.4f}"
            table.add_row(anomaly.unit_name, score_str)
        output_elements.append(table)
    if output_elements:
        final_panel = Panel(
            Group(*output_elements), title=title, border_style=border_style, expand=False
        )
        console.print(final_panel)


def format_llm_report(result: Optional[LLMAnalysisResult], console: Console) -> None:
    """Formats and prints the LLM Analysis results using Rich."""
    log.debug(f"format_llm_report called with result object: {result is not None}")
    title = "LLM Synthesis & Recommendations"
    border_style = "green"
    if not result:
        log.debug("Skipping LLM report formatting (no result data).")
        return
    output_elements = []
    if result.error:
        output_elements.append(f"[red]LLM Analysis Error: {result.error}[/red]")
        border_style = "red"
    meta_parts = []
    if result.provider_used:
        meta_parts.append(f"Provider: {result.provider_used}")
    if result.model_used:
        meta_parts.append(f"Model: {result.model_used}")
    if result.prompt_token_count is not None:
        meta_parts.append(f"Prompt Tokens: {result.prompt_token_count}")
    if result.completion_token_count is not None:
        meta_parts.append(f"Completion Tokens: {result.completion_token_count}")
    if meta_parts:
        output_elements.append(f"[dim]{' | '.join(meta_parts)}[/dim]")
    if result.synthesis:
        if output_elements:
            output_elements.append("")
        try:
            md = Markdown(result.synthesis)
            output_elements.append(md)
        except Exception as e:
            log.error(
                f"Error rendering LLM synthesis as Markdown: {e}. Falling back to plain text."
            )
            output_elements.append(result.synthesis)
    elif not result.error:
        output_elements.append("\n[dim]LLM did not produce a synthesis.[/dim]")

    md_object = None
    str_elements = []
    for el in output_elements:
        if isinstance(el, Markdown):
            md_object = el
        else:
            str_elements.append(str(el))
    final_content_str = "\n".join(str_elements).strip()
    if final_content_str or md_object:
        content_group = Group(*str_elements) if str_elements else None
        panel_content: Any
        if content_group and md_object:
            panel_content = Group(content_group, Padding(md_object, (1, 0, 0, 0)))
        elif md_object:
            panel_content = md_object
        else:
            panel_content = content_group

        if panel_content:
            console.print(
                Panel(panel_content, title=title, border_style=border_style, expand=True)
            )

def format_ebpf_report(result: Optional[EBPFAnalysisResult], console: Console) -> None:
    """Formats and prints the eBPF Analysis results using Rich."""
    log.debug(f"format_ebpf_report called with result object: {result is not None}")
    title = "eBPF Process Tracing"
    border_style = "blue"
    if not result:
        log.debug("Skipping eBPF report formatting (no result data).")
        return

    try:
        boot_time_unix = psutil.boot_time()
    except Exception as e:
        log.error(f"Could not get system boot time from psutil: {e}. eBPF timestamps will be incorrect.")
        boot_time_unix = 0.0

    output_elements: List[Any] = []
    if result.error:
        output_elements.append(f"[red]eBPF Analysis Error: {result.error}[/red]")
        border_style = "red"

    exec_count = len(result.exec_events)
    exit_count = len(result.exit_events)
    output_elements.append(f"[dim]Events Captured: Execs={exec_count}, Exits={exit_count}[/dim]")

    if not result.exec_events and not result.exit_events and not result.error:
        output_elements.append("\n[dim]No eBPF process events captured during analysis window.[/dim]")
    else:
        if result.exec_events:
            exec_table = Table(title=f"Recent Process Executions (eBPF - Last {MAX_EBPF_EVENTS_TO_SHOW})", show_header=True, header_style="bold blue", expand=True)
            exec_table.add_column("Timestamp", style="dim", width=26)
            exec_table.add_column("PID", style="green", width=8)
            exec_table.add_column("PPID", style="blue", width=8)
            exec_table.add_column("Comm", style="cyan", width=16)
            exec_table.add_column("Filename", style="magenta")
            for event in result.exec_events[-MAX_EBPF_EVENTS_TO_SHOW:]:
                event_time_unix = boot_time_unix + (event.timestamp_ns / 1e9)
                ts = datetime.datetime.fromtimestamp(event_time_unix, tz=datetime.timezone.utc)
                ts_str = ts.isoformat(timespec="milliseconds")
                exec_table.add_row(ts_str, str(event.pid), str(event.ppid), event.comm, event.filename)
            output_elements.append(exec_table)

        if result.exit_events:
            exit_table = Table(title=f"Recent Process Exits (eBPF - Last {MAX_EBPF_EVENTS_TO_SHOW})", show_header=True, header_style="bold blue", expand=True)
            exit_table.add_column("Timestamp", style="dim", width=26)
            exit_table.add_column("PID", style="green", width=8)
            exit_table.add_column("PPID", style="blue", width=8)
            exit_table.add_column("Comm", style="cyan", width=16)
            exit_table.add_column("Exit Code", style="yellow", width=10)
            for event in result.exit_events[-MAX_EBPF_EVENTS_TO_SHOW:]:
                event_time_unix = boot_time_unix + (event.timestamp_ns / 1e9)
                ts = datetime.datetime.fromtimestamp(event_time_unix, tz=datetime.timezone.utc)
                ts_str = ts.isoformat(timespec="milliseconds")
                exit_code_str = str(event.exit_code)
                if event.exit_code != 0:
                    exit_code_str = f"[bold red]{exit_code_str}[/bold red]"
                exit_table.add_row(ts_str, str(event.pid), str(event.ppid), event.comm, exit_code_str)
            output_elements.append(exit_table)

    valid_elements = [elem for elem in output_elements if elem]
    if valid_elements:
        console.print(Panel(Group(*valid_elements), title=title, border_style=border_style, expand=False))

# --- Single Unit Report Formatting ---
def format_rich_single_unit_report(
    report: Optional[SingleUnitReport], console: Console
) -> None:
    """Formats the focused single unit report using Rich."""
    if not report:
        console.print(Panel("[bold red]Error: No analysis report generated for the unit.[/bold red]"))
        return

    if report.analysis_error:
        console.print(Panel(f"[bold red]Error:[/bold red] {report.analysis_error}"))
        return

    unit = report.unit_info
    if not unit:
        console.print(Panel("[bold red]Error: Unit information is missing from the report.[/bold red]"))
        return

    # --- Header Panel ---
    console.print(Panel(
        f"[bold cyan]{unit.name}[/bold cyan]\n{unit.description or '[dim]No description[/dim]'}",
        title="Unit Overview", border_style="green"
    ))

    # --- Main Info Table ---
    main_table = Table.grid(expand=True, padding=(0, 2))
    main_table.add_column(ratio=1)
    main_table.add_column(ratio=2)

    color = 'green' if unit.active_state == 'active' else 'red' if unit.active_state == 'failed' else 'yellow'
    state_text = f"[bold {color}]{unit.active_state or 'N/A'}[/bold {color}] ({unit.sub_state or 'N/A'})"

    main_table.add_row("[bold]Load State:[/bold]", unit.load_state or "[dim]N/A[/dim]")
    main_table.add_row("[bold]Active State:[/bold]", state_text)
    if unit.details.get('Result'):
        main_table.add_row("[bold]Last Result:[/bold]", str(unit.details.get('Result')))
    if unit.details.get('MainPID'):
        main_table.add_row("[bold]Main PID:[/bold]", str(unit.details.get('MainPID')))
    if unit.details.get('NRestarts'):
        main_table.add_row("[bold]Restarts:[/bold]", str(unit.details.get('NRestarts')))
    if unit.path:
        main_table.add_row("[bold]DBus Path:[/bold]", f"[dim]{unit.path}[/dim]")

    console.print(Panel(main_table, title="Status & Properties", border_style="blue"))

    # --- Resource Usage ---
    if report.resource_usage:
        res = report.resource_usage
        res_table = Table.grid(expand=True, padding=(0, 2))
        res_table.add_column(ratio=1)
        res_table.add_column(ratio=2)
        res_table.add_row("[bold]CPU Time:[/bold]", _format_nanoseconds(res.cpu_usage_nsec))
        res_table.add_row("[bold]Current Memory:[/bold]", _format_bytes(res.memory_current_bytes))
        res_table.add_row("[bold]Peak Memory:[/bold]", _format_bytes(res.memory_peak_bytes))
        res_table.add_row("[bold]I/O Read:[/bold]", _format_bytes(res.io_read_bytes))
        res_table.add_row("[bold]I/O Write:[/bold]", _format_bytes(res.io_write_bytes))
        res_table.add_row("[bold]Tasks:[/bold]", str(res.tasks_current or 0))
        if res.error:
            res_table.add_row("[bold red]Error:[/bold red]", res.error)
        console.print(Panel(res_table, title="Resource Usage (cgroup)", border_style="yellow"))

    # --- Dependencies ---
    if report.dependency_info:
        dep_info = report.dependency_info
        dep_content = []
        if dep_info.error:
            dep_content.append(f"[red]Error analyzing dependencies: {dep_info.error}[/red]")
        dep_table = _format_dependency_table(dep_info)
        if dep_table:
            dep_content.append(dep_table)
        elif not dep_info.error:
            dep_content.append("[dim]No dependencies found.[/dim]")
        if dep_content:
            console.print(Panel(Group(*dep_content), title="Dependencies", border_style="cyan"))

    # --- Logs ---
    if unit.recent_logs:
        log_panel_content = _format_log_snippet(unit.recent_logs, max_lines=50)
        console.print(Panel(log_panel_content, title=f"Recent Logs (Last {len(unit.recent_logs)})", border_style="magenta"))      

def format_json_single_unit_report(report: Optional[SingleUnitReport]) -> str:
    """Formats the single unit report as a JSON string."""
    if report is None:
        return json.dumps({"error": "No analysis report generated for the unit."}, indent=2)
    try:
        report_dict = asdict(report)
        return json.dumps(report_dict, indent=2, default=str)
    except Exception as e:
        log.error(f"Failed to serialize single unit report to JSON: {e}")
        return json.dumps(
            {"error": "Failed to serialize report", "details": str(e)}, indent=2
        )


# --- Full Report Formatting ---
def format_rich_report(report: Optional[SystemReport], console: Console) -> None:
    """Formats the full system report using Rich."""
    log.debug("format_rich_report called.")
    if report is None:
        console.print(
            Panel(
                "[bold red]Error: No analysis report generated.[/bold red]",
                title="Error",
                border_style="red",
            )
        )
        return
    console.print(
        Panel(
            f"[bold cyan]Sysdiag Analyzer Report[/bold cyan]\nHostname: {report.hostname or 'N/A'}\nTimestamp: {report.timestamp or 'N/A'}\nBoot ID: {report.boot_id or 'N/A'}",
            title="System Overview",
            border_style="green",
            expand=False,
        )
    )
    if report.boot_analysis:
        format_boot_report(report.boot_analysis, console)
    else:
        console.print(
            Panel(
                "[dim]No boot analysis performed or data available.[/dim]",
                title="Boot Analysis",
                border_style="dim",
            )
        )
    if report.health_analysis:
        format_health_report(report.health_analysis, console)
    else:
        console.print(
            Panel(
                "[dim]No health analysis performed or data available.[/dim]",
                title="Service Health Analysis",
                border_style="dim",
            )
        )
    if report.resource_analysis:
        format_resource_report(report.resource_analysis, console)
    else:
        console.print(
            Panel(
                "[dim]No resource analysis performed or data available.[/dim]",
                title="Resource Analysis",
                border_style="dim",
            )
        )
    if report.log_analysis:
        format_log_report(report.log_analysis, console)
    else:
        console.print(
            Panel(
                "[dim]No log analysis performed or data available.[/dim]",
                title="Log Analysis",
                border_style="dim",
            )
        )
    if report.dependency_analysis:
        format_dependency_report(report.dependency_analysis, console)
    else:
        console.print(
            Panel(
                "[dim]No dependency analysis for failed units performed or data available.[/dim]",
                title="Dependency Analysis for Failed Units",
                border_style="dim",
            )
        )
    if report.full_dependency_analysis:
        format_full_dependency_report(report.full_dependency_analysis, console)
    if report.ebpf_analysis:
        format_ebpf_report(report.ebpf_analysis, console)
    if report.ml_analysis:
        format_ml_report(report.ml_analysis, console)
    if report.llm_analysis:
        format_llm_report(report.llm_analysis, console)
    if report.errors:
        error_text = "\n".join(f"- [red]{err}[/red]" for err in report.errors)
        console.print(
            Panel(
                error_text, title="Overall Analysis Errors", border_style="red", expand=False
            )
        )
    log.debug("format_rich_report finished.")


def format_json_report(report: Optional[SystemReport]) -> str:
    """Formats the full system report as a JSON string."""
    if report is None:
        return json.dumps({"error": "No analysis report generated."}, indent=2)
    try:
        report_dict = asdict(report)
        return json.dumps(report_dict, indent=2, default=str)
    except Exception as e:
        log.error(f"Failed to serialize report to JSON: {e}")
        return json.dumps(
            {"error": "Failed to serialize report", "details": str(e)}, indent=2
        )