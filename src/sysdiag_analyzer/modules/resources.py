# src/sysdiag_analyzer/modules/resources.py
# -*- coding: utf-8 -*-

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil

try:
    import dbus
    import dbus.exceptions  # Import exceptions submodule

    try:
        from ..modules.health import (
            _dbus_to_python,
            _get_unit_properties_dbus,
            _get_unit_properties_fallback,
        )
    except ImportError:

        def _dbus_to_python(val):
            return val

        def _get_unit_properties_dbus(bus, path):
            return None

        def _get_unit_properties_fallback(name):
            return None

    HAS_DBUS = True
except ImportError:
    HAS_DBUS = False
    dbus = None

    def _dbus_to_python(val):  # Dummy function
        return val

    def _get_unit_properties_dbus(bus, path):
        return None

    def _get_unit_properties_fallback(name):
        return None


# Local imports
from ..datatypes import (
    ChildProcessGroupUsage,
    ResourceAnalysisResult,
    SystemResourceUsage,
    UnitHealthInfo,  # Needed for input type hint
    UnitResourceUsage,
)

log = logging.getLogger(__name__)
log_cgroup = logging.getLogger(__name__ + ".cgroup")
log_child_proc = logging.getLogger(__name__ + ".child_proc")
log_dbus_res = logging.getLogger(__name__ + ".dbus_res")
log_dbus_res.setLevel(logging.WARNING)

# --- Constants ---
CGROUP_BASE_PATH = Path("/sys/fs/cgroup")
TOP_N_COUNT = 10
CHILD_PROCESS_SCAN_DEPTH = 5
# MODIFIED: Removed CHILD_PROCESS_CPU_INTERVAL as it's no longer needed.
CHILD_PROCESS_MAX_GROUPS = 50
CHILD_PROCESS_MIN_MEM_MB = 5
# MODIFIED: Replaced percentage threshold with a cumulative seconds threshold.
CHILD_PROCESS_MIN_CPU_SECONDS = 60.0


# --- Cgroup Helper Functions ---
def _read_cgroup_file(path: Path) -> Optional[str]:
    """Safely reads a cgroup file content."""
    # (Logic remains the same)
    if not path.is_file():
        log_cgroup.debug(f"Cgroup file not found: {path}")
        return None
    try:
        content_bytes = path.read_bytes()
        return content_bytes.decode("utf-8", errors="replace").strip()
    except PermissionError:
        log_cgroup.warning(f"Permission denied reading cgroup file: {path}")
        return None
    except OSError as e:
        log_cgroup.error(f"OS error reading cgroup file {path}: {e}")
        return None
    except Exception as e:
        log_cgroup.exception(f"Unexpected error reading cgroup file {path}: {e}")
        return None


def _parse_cgroup_kv(content: Optional[str]) -> Dict[str, int]:
    """Parses space-separated key-value pairs from cgroup file content."""
    # (Logic remains the same)
    data = {}
    if content is None:
        return data
    try:
        for line_num, line in enumerate(content.splitlines()):
            parts = line.split()
            if len(parts) == 2:
                key = parts[0]
                try:
                    value_str = parts[1]
                    if value_str == "max":
                        continue
                    value = int(value_str)
                    data[key] = value
                except ValueError:
                    log_cgroup.warning(
                        f"Non-integer value found for key '{key}' in kv content: {parts[1]}"
                    )
            elif line.strip():
                log_cgroup.warning(
                    f"Skipping line with unexpected format in kv content (line {line_num+1}): {line!r}"
                )
    except Exception as e:
        log_cgroup.exception(f"Error parsing key-value cgroup content: {e}")
    return data


def _parse_cgroup_cpu_stat(content: Optional[str]) -> Optional[int]:
    """Parses 'usage_usec' from cpu.stat content and returns nanoseconds."""
    # (Logic remains the same)
    if content is None:
        return None
    data: Dict[str, int] = {}
    usage_usec: Optional[int] = None  # Initialize usage_usec
    try:
        for line in content.splitlines():
            parts = line.split()
            if len(parts) == 2:
                key = parts[0]
                try:
                    value = int(parts[1])
                    data[key] = value
                    # Store usage_usec immediately if found
                    if key == "usage_usec":
                        usage_usec = value
                except ValueError:
                    log_cgroup.warning(
                        f"Non-integer value for key '{key}' in cpu.stat: {parts[1]}"
                    )
            elif line.strip():
                log_cgroup.warning(f"Skipping unexpected line format in cpu.stat: {line!r}")
        # Return converted value if found
        if usage_usec is not None:
            return usage_usec * 1000  # Convert microseconds to nanoseconds
        else:
            # Log as WARNING if key not found but content existed and was parsed
            log_cgroup.warning(
                f"Could not find 'usage_usec' in parsed cpu.stat data: {data}"
            )
            return None
    except Exception as e:
        log_cgroup.exception(f"Error parsing cpu.stat content: {e}")
        return None


def _parse_cgroup_memory(content: Optional[str]) -> Optional[int]:
    """Parses a single integer value from memory cgroup files."""
    # (Logic remains the same)
    if content is None:
        return None
    try:
        if content == "max":
            return None  # Or a sentinel like -1 if needed
        return int(content)
    except (ValueError, TypeError):
        log_cgroup.warning(
            f"Could not parse integer from memory cgroup content: {content[:100]}"
        )
        return None


IO_STAT_DEVICE_LINE_PATTERN = re.compile(r"^\d+:\d+\s+")


def _parse_cgroup_io_stat(content: Optional[str]) -> Tuple[Optional[int], Optional[int]]:
    """Parses 'rbytes' and 'wbytes' from io.stat content."""
    # (Logic remains the same)
    if content is None:
        log_cgroup.debug("io.stat content is None, returning None, None.")
        return None, None
    rbytes_sum = 0
    wbytes_sum = 0
    found_any_valid_key = False
    log_cgroup.debug("--- Parsing io.stat content ---")
    log_cgroup.debug(f"Raw content snippet: {content[:200]}...")
    try:
        for line_num, line in enumerate(content.splitlines()):
            line_strip = line.strip()
            if not line_strip:
                log_cgroup.debug(f"Line {line_num+1}: Skipping blank line.")
                continue
            if IO_STAT_DEVICE_LINE_PATTERN.match(line_strip):
                log_cgroup.debug(
                    f"Line {line_num+1}: Skipping device-specific line: '{line_strip}'"
                )
                continue
            log_cgroup.debug(
                f"Line {line_num+1}: Processing aggregate line: '{line_strip}'"
            )
            for part_num, part in enumerate(line_strip.split()):
                log_cgroup.debug(f"  Part {part_num+1}: '{part}'")
                if "=" in part:
                    try:
                        key, value_str = part.split("=", 1)
                        log_cgroup.debug(
                            f"    Found '=': key='{key}', value_str='{value_str}'"
                        )
                        if key in ["rbytes", "wbytes"]:
                            log_cgroup.debug(
                                f"      Key matches '{key}'. Checking if value '{value_str}' is digit..."
                            )
                            if value_str.isdigit():
                                value = int(value_str)
                                log_cgroup.debug(f"        Value is digit. Parsed value: {value}")
                                if key == "rbytes":
                                    rbytes_sum += value
                                    log_cgroup.debug(
                                        f"        Added to rbytes_sum. New sum: {rbytes_sum}"
                                    )
                                elif key == "wbytes":
                                    wbytes_sum += value
                                    log_cgroup.debug(
                                        f"        Added to wbytes_sum. New sum: {wbytes_sum}"
                                    )
                                found_any_valid_key = True
                            else:
                                log_cgroup.warning(
                                    f"      Value '{value_str}' is not purely digits for key '{key}'. Skipping."
                                )
                    except ValueError as e:
                        log_cgroup.warning(f"    ValueError processing part '{part}': {e}")
                    except Exception as e_inner:
                        log_cgroup.warning(
                            f"    Unexpected error processing part '{part}': {e_inner}",
                            exc_info=True,
                        )
    except Exception as e:
        log_cgroup.exception(f"Error during main loop of parsing io.stat content: {e}")
        return None, None
    log_cgroup.debug("--- Finished parsing io.stat ---")
    log_cgroup.debug(f"Final sums: rbytes={rbytes_sum}, wbytes={wbytes_sum}")
    log_cgroup.debug(f"Found any valid key: {found_any_valid_key}")
    if found_any_valid_key:
        return rbytes_sum, wbytes_sum
    elif content:
        log_cgroup.debug(
            "No rbytes/wbytes keys found or parsed in aggregate io.stat lines (returning 0, 0)."
        )
        return 0, 0
    else:
        log_cgroup.debug("io.stat file was empty (returning 0, 0).")
        return 0, 0


def _parse_cgroup_tasks(content: Optional[str]) -> Optional[int]:
    """Counts the number of PIDs listed in cgroup.procs."""
    # (Logic remains the same)
    if content is None:
        return 0
    if content == "":
        return 0
    try:
        pids = [line for line in content.splitlines() if line.strip()]
        return len(pids)
    except Exception as e:
        log_cgroup.exception(f"Error parsing tasks from cgroup.procs content: {e}")
        return None


# In src/sysdiag_analyzer/modules/resources.py


def _get_unit_cgroup_path(unit_name: str, dbus_manager: Optional[Any]) -> Optional[str]:
    """
    Gets the relative cgroup path for a unit using DBus Introspection to find the correct interface.
    """
    log_dbus = log_dbus_res
    log_dbus.debug(
        f"--- Starting cgroup path lookup for unit: {unit_name} (Introspection Logic) ---"
    )
    if not HAS_DBUS or not dbus or not dbus_manager or not hasattr(dbus_manager, "bus"):
        log_dbus.debug("DBus dependencies not met, cannot get cgroup path.")
        return None

    dbus_bus = dbus_manager.bus
    if dbus_bus is None:
        log_dbus.warning("DBus manager object has 'bus' attribute, but it is None.")
        return None

    try:
        log_dbus.debug(f"Calling manager.GetUnit('{unit_name}')...")
        unit_path = dbus_manager.GetUnit(unit_name)
        log_dbus.debug(f"manager.GetUnit returned path: {unit_path}")

        unit_object = dbus_bus.get_object("org.freedesktop.systemd1", unit_path)

        # 1. Introspect the object to find its interfaces
        introspect_interface = dbus.Interface(
            unit_object, "org.freedesktop.DBus.Introspectable"
        )
        xml_data = introspect_interface.Introspect()

        # 2. Find the correct interface that holds the ControlGroup property
        # These are the most likely candidates to have a cgroup
        candidate_interfaces = [
            "org.freedesktop.systemd1.Service",
            "org.freedesktop.systemd1.Slice",
            "org.freedesktop.systemd1.Scope",
        ]
        interface_to_use = None
        for iface in candidate_interfaces:
            if iface in xml_data:
                interface_to_use = iface
                log_dbus.debug(
                    f"Found suitable interface '{iface}' for {unit_name} via introspection."
                )
                break

        if not interface_to_use:
            log_dbus.debug(
                f"No suitable interface with a cgroup found for unit '{unit_name}'. This is expected for types like .target, .device, etc."
            )
            return None

        # 3. Get the property from the specific interface we found
        properties_interface = dbus.Interface(
            unit_object, "org.freedesktop.DBus.Properties"
        )
        cgroup_path_prop = properties_interface.Get(interface_to_use, "ControlGroup")
        log_dbus.debug(
            f"Successfully got ControlGroup property from '{interface_to_use}': {cgroup_path_prop!r}"
        )

        relative_path = str(cgroup_path_prop).lstrip("/")
        if not relative_path:
            log_dbus.debug(
                f"ControlGroup property for {unit_name} is empty. Treating as no path."
            )
            return None

        log_dbus.info(f"Successfully found cgroup path for {unit_name}: {relative_path}")
        return relative_path

    except dbus.exceptions.DBusException as e:
        dbus_error_name = getattr(e, "_dbus_error_name", "UnknownDBusError")
        # This is now a more specific warning, as some units are expected to fail here.
        log_dbus.debug(
            f"DBusException during cgroup path lookup for '{unit_name}': {e} (Error: {dbus_error_name})"
        )
        return None
    except Exception as e:
        log_dbus.error(
            f"Unexpected error getting cgroup path for {unit_name}: {e}", exc_info=True
        )
        return None


def _get_service_pids(
    units: List[UnitHealthInfo], dbus_manager: Optional[Any]
) -> Dict[str, Optional[int]]:
    """Extracts the main PID for active service units from the provided list."""
    # (Logic remains the same, uses provided units list)
    service_pids: Dict[str, Optional[int]] = {}
    dbus_bus = getattr(dbus_manager, "bus", None) if dbus_manager and HAS_DBUS else None
    active_services_count = 0
    pids_found_count = 0
    log_child_proc.debug(
        f"Attempting to fetch PIDs for active services from {len(units)} provided units..."
    )
    for unit in units:
        # Only consider active services
        if not unit.name.endswith(".service") or unit.active_state != "active":
            continue
        active_services_count += 1
        unit_name = unit.name
        pid: Optional[int] = None
        # Use details if already present and is a dict
        details = unit.details if isinstance(unit.details, dict) else None
        # If details are missing or don't contain MainPID, try to fetch them now
        if details is None or "MainPID" not in details:
            log_child_proc.debug(
                f"Details missing or lack MainPID for active service {unit_name}, attempting fetch..."
            )
            fetched_details: Optional[Dict[str, Any]] = None
            if dbus_bus and unit.path:
                fetched_details = _get_unit_properties_dbus(dbus_bus, unit.path)
            if fetched_details is None:  # Fallback
                fetched_details = _get_unit_properties_fallback(unit_name)
            # Update unit.details in-place if fetch was successful
            if isinstance(fetched_details, dict):
                unit.details = fetched_details  # Modify the object in the list
                details = unit.details  # Use the newly fetched details
                log_child_proc.debug(
                    f"Fetched details for {unit_name} to find MainPID."
                )
            else:
                log_child_proc.warning(
                    f"Could not fetch properties for active service {unit_name} to get MainPID."
                )
                unit.details = {}  # Ensure details is a dict on failure
        # Now extract PID from details (which should be a dict)
        if isinstance(details, dict):
            pid_val = details.get("MainPID")
            if pid_val is not None:
                try:
                    pid_int = int(pid_val)
                    if pid_int > 0:
                        pid = pid_int
                        pids_found_count += 1
                        # Log moved to after assignment
                    else:
                        log_child_proc.debug(
                            f"Ignoring MainPID {pid_int} for service {unit_name}"
                        )
                except (ValueError, TypeError):
                    log_child_proc.warning(
                        f"Could not parse MainPID '{pid_val}' for service {unit_name}"
                    )
        service_pids[unit_name] = pid
        if pid:
            log_child_proc.debug(
                f"Stored MainPID {pid} for active service {unit_name}."
            )
    log_child_proc.debug(
        f"Checked {active_services_count} active services, found {pids_found_count} usable MainPIDs."
    )
    return service_pids


def _normalize_cmdline(cmdline: List[str]) -> str:
    """Creates a normalized command name from a process cmdline list."""
    # (Logic remains the same)
    if not cmdline:
        return "[unknown]"
    # Use the first argument, attempt to strip path
    base_cmd = os.path.basename(cmdline[0])
    # Simple normalization: lowercase, maybe remove common extensions?
    return base_cmd.lower()


def _scan_and_group_child_processes(
    service_pids: Dict[str, Optional[int]]
) -> List[ChildProcessGroupUsage]:
    """Scans process tree, groups by command, aggregates resources."""
    log_child_proc.info("Scanning for child process groups...")
    groups: Dict[
        Tuple[str, str], ChildProcessGroupUsage
    ] = {}  # (parent_unit, cmd_name) -> GroupData
    processed_pids: Set[int] = set()  # Avoid processing the same PID multiple times

    for unit_name, main_pid in service_pids.items():
        if main_pid is None or main_pid == 0:
            continue
        try:
            parent_proc = psutil.Process(main_pid)
            children = parent_proc.children(recursive=True)
            log_child_proc.debug(
                f"Found {len(children)} recursive children for {unit_name} (PID: {main_pid})"
            )
            for child in children:
                if child.pid in processed_pids:
                    continue
                processed_pids.add(child.pid)
                try:
                    # Fetch attributes needed, handle potential errors individually
                    with child.oneshot():  # Use oneshot for efficiency
                        cmdline = child.cmdline()
                        mem_info = child.memory_info()
                        # MODIFIED: Get cumulative CPU time instead of percentage.
                        cpu_times = child.cpu_times()

                    if not cmdline:
                        log_child_proc.debug(
                            f"Skipping child PID {child.pid} (parent: {main_pid}) - empty cmdline"
                        )
                        continue
                    # Normalize command name
                    cmd_name = _normalize_cmdline(cmdline)
                    group_key = (unit_name, cmd_name)
                    if group_key not in groups:
                        groups[group_key] = ChildProcessGroupUsage(
                            command_name=cmd_name,
                            parent_unit=unit_name,
                            process_count=0,
                            pids=[],
                            aggregated_cpu_seconds_total=0.0,
                            aggregated_memory_bytes=0,
                        )
                    group = groups[group_key]
                    group.process_count += 1
                    if len(group.pids) < 5:  # Store a few example PIDs
                        group.pids.append(child.pid)

                    if (
                        group.aggregated_cpu_seconds_total is not None
                        and cpu_times is not None
                    ):
                        group.aggregated_cpu_seconds_total += (
                            cpu_times.user + cpu_times.system
                        )

                    if group.aggregated_memory_bytes is not None and mem_info:
                        group.aggregated_memory_bytes += mem_info.rss
                except psutil.NoSuchProcess:
                    log_child_proc.debug(
                        f"Child process {child.pid} disappeared during analysis."
                    )
                except psutil.AccessDenied:
                    log_child_proc.warning(
                        f"Access denied getting info for child process {child.pid} of {unit_name}"
                    )
                except Exception as child_e:
                    log_child_proc.error(
                        f"Error processing child {child.pid} of {unit_name}: {child_e}",
                        exc_info=False,
                    )  # Avoid excessive logging
        except psutil.NoSuchProcess:
            log_child_proc.debug(
                f"Main service process {main_pid} for {unit_name} disappeared during child scan."
            )
        except psutil.AccessDenied:
            log_child_proc.warning(
                f"Access denied accessing main service process {main_pid} for {unit_name}"
            )
        except Exception as parent_e:
            log_child_proc.error(
                f"Error processing children of {unit_name} (PID: {main_pid}): {parent_e}",
                exc_info=False,
            )
    # Filter groups based on thresholds
    filtered_groups = []
    for group in groups.values():
        mem_mb = (group.aggregated_memory_bytes or 0) / (1024 * 1024)
        cpu_sec = group.aggregated_cpu_seconds_total or 0.0
        if group.process_count > 0 and (
            mem_mb >= CHILD_PROCESS_MIN_MEM_MB
            or cpu_sec >= CHILD_PROCESS_MIN_CPU_SECONDS
        ):
            filtered_groups.append(group)
        else:
            log_child_proc.debug(
                f"Filtering out group '{group.command_name}' under parent '{group.parent_unit}' (Count: {group.process_count}, CPU: {cpu_sec:.1f}s, Mem: {mem_mb:.1f}MB)"
            )
    # Sort and limit results
    filtered_groups.sort(
        key=lambda g: (g.aggregated_cpu_seconds_total or 0.0, g.aggregated_memory_bytes or 0),
        reverse=True,
    )
    final_groups = filtered_groups[:CHILD_PROCESS_MAX_GROUPS]
    log_child_proc.info(
        f"Child process scan complete. Found {len(groups)} initial groups, reporting {len(final_groups)} groups after filtering."
    )
    return final_groups


# --- Main Logic Functions ---
def get_system_wide_usage() -> SystemResourceUsage:
    """Gathers system-wide resource usage metrics using psutil."""
    # (Logic remains the same)
    log.debug("Getting system-wide resource usage via psutil...")
    usage = SystemResourceUsage()
    try:
        try:
            usage.cpu_percent = psutil.cpu_percent(interval=0.1, percpu=False)
        except Exception as cpu_e:
            log.warning(f"psutil.cpu_percent failed: {cpu_e}")
            usage.error = f"CPU Usage Error: {cpu_e}"
        mem = psutil.virtual_memory()
        usage.mem_total_bytes = mem.total
        usage.mem_available_bytes = mem.available
        usage.mem_percent = mem.percent
        swap = psutil.swap_memory()
        usage.swap_total_bytes = swap.total
        usage.swap_used_bytes = swap.used
        usage.swap_percent = swap.percent
        try:
            disk_io = psutil.disk_io_counters(perdisk=False)
            if disk_io:
                usage.disk_io_read_bytes = disk_io.read_bytes
                usage.disk_io_write_bytes = disk_io.write_bytes
        except Exception as disk_e:
            log.warning(f"psutil.disk_io_counters failed: {disk_e}")
            disk_err_str = f"Disk IO Error: {disk_e}"
            usage.error = (
                f"{usage.error}; {disk_err_str}" if usage.error else disk_err_str
            )
        try:
            net_io = psutil.net_io_counters(pernic=False)
            if net_io:
                usage.net_io_sent_bytes = net_io.bytes_sent
                usage.net_io_recv_bytes = net_io.bytes_recv
        except Exception as net_e:
            log.warning(f"psutil.net_io_counters failed: {net_e}")
            net_err_str = f"Net IO Error: {net_e}"
            usage.error = f"{usage.error}; {net_err_str}" if usage.error else net_err_str
    except Exception as e:
        log.exception(f"Error getting system-wide usage via psutil: {e}")
        err_str = f"psutil error: {e}"
        usage.error = f"{usage.error}; {err_str}" if usage.error else err_str
    log.debug(f"System usage fetched: CPU={usage.cpu_percent}%, Mem={usage.mem_percent}%")
    return usage


def get_unit_resource_usage(
    units: List[UnitHealthInfo], dbus_manager: Optional[Any]
) -> List[UnitResourceUsage]:
    """Gathers resource usage for a list of units via cgroup v2 files."""
    # (Logic remains the same)
    log.debug(f"Getting resource usage for {len(units)} units via cgroups...")
    results: List[UnitResourceUsage] = []
    if not CGROUP_BASE_PATH.is_dir():
        log.error(
            f"Cgroup base path {CGROUP_BASE_PATH} not found. Cannot collect per-unit cgroup stats."
        )
        return results
    for unit_info in units:
        unit_name = unit_info.name
        usage = UnitResourceUsage(name=unit_name)
        error_parts = []
        relative_cgroup_path = _get_unit_cgroup_path(unit_name, dbus_manager)
        if not relative_cgroup_path:
            log_cgroup.debug(
                f"Skipping cgroup resource collection for {unit_name}: No cgroup path found."
            )
            results.append(usage)
            continue
        usage.cgroup_path = relative_cgroup_path
        full_cgroup_path = CGROUP_BASE_PATH / relative_cgroup_path
        if not full_cgroup_path.is_dir():
            log_cgroup.warning(
                f"Specific cgroup directory not found: {full_cgroup_path}. Skipping resource collection for {unit_name}."
            )
            results.append(usage)
            continue
        cpu_stat_content = _read_cgroup_file(full_cgroup_path / "cpu.stat")
        mem_current_content = _read_cgroup_file(full_cgroup_path / "memory.current")
        mem_peak_content = _read_cgroup_file(full_cgroup_path / "memory.peak")  # Optional
        io_stat_content = _read_cgroup_file(full_cgroup_path / "io.stat")
        tasks_content = _read_cgroup_file(full_cgroup_path / "cgroup.procs")
        usage.cpu_usage_nsec = _parse_cgroup_cpu_stat(cpu_stat_content)
        if usage.cpu_usage_nsec is None and cpu_stat_content is not None:
            error_parts.append("Failed to parse cpu.stat")
        usage.memory_current_bytes = _parse_cgroup_memory(mem_current_content)
        if usage.memory_current_bytes is None and mem_current_content is not None:
            error_parts.append("Failed to parse memory.current")
        usage.memory_peak_bytes = _parse_cgroup_memory(mem_peak_content)
        if usage.memory_peak_bytes is None and mem_peak_content is not None:
            log_cgroup.debug(f"Failed to parse memory.peak for {unit_name}")
        log_cgroup.debug(
            f"Calling _parse_cgroup_io_stat for {unit_name} with content (snippet): {io_stat_content[:100] if io_stat_content else 'None'}..."
        )
        rbytes, wbytes = _parse_cgroup_io_stat(io_stat_content)
        log_cgroup.debug(
            f"Parser _parse_cgroup_io_stat for {unit_name} returned: rbytes={rbytes}, wbytes={wbytes}"
        )
        usage.io_read_bytes = rbytes
        usage.io_write_bytes = wbytes
        if rbytes is None and wbytes is None and io_stat_content is not None:
            error_parts.append("Failed to parse io.stat")
        usage.tasks_current = _parse_cgroup_tasks(tasks_content)
        if usage.tasks_current is None and tasks_content is not None:
            error_parts.append("Failed to parse cgroup.procs")
        if error_parts:
            usage.error = "; ".join(error_parts)
            log.warning(
                f"Partial errors fetching resources for {unit_name}: {usage.error}"
            )
        log_cgroup.debug(
            f"FINAL VALUES for {unit_name}: Path: {usage.cgroup_path}, CPU(ns): {usage.cpu_usage_nsec}, "
            f"Mem(B): {usage.memory_current_bytes}, IO(R/W B): {usage.io_read_bytes}/{usage.io_write_bytes}, "
            f"Tasks: {usage.tasks_current}, Error: {usage.error}"
        )
        results.append(usage)
    log.debug(
        f"Finished collecting cgroup resource usage for {len(results)} units."
    )
    return results


# --- Main Analysis Function (Modified Signature) ---
def analyze_resources(
    units: List[UnitHealthInfo],  # Expects the fetched list
    dbus_manager: Optional[Any],
) -> ResourceAnalysisResult:
    """
    Orchestrates resource analysis: gathers system and per-unit metrics,
    monitors child process groups, and identifies top consumers.
    """
    log.info("Starting resource analysis...")
    result = ResourceAnalysisResult()

    # 1. Get System-Wide Usage
    try:
        result.system_usage = get_system_wide_usage()
        if result.system_usage and result.system_usage.error:
            # Combine system usage error with overall analysis error
            sys_err = f"System Usage Error: {result.system_usage.error}"
            result.analysis_error = (
                f"{result.analysis_error}; {sys_err}"
                if result.analysis_error
                else sys_err
            )
    except Exception as e:
        log.exception("Unexpected error getting system-wide usage.")
        err_msg = f"Failed to get system usage: {e}"
        result.analysis_error = (
            f"{result.analysis_error}; {err_msg}" if result.analysis_error else err_msg
        )
        # Ensure system_usage object exists even on error
        result.system_usage = SystemResourceUsage(error=str(e))

    # 2. Get Per-Unit Usage (Requires provided unit list and DBus manager)
    if not units:
        log.warning("No units provided for per-unit resource analysis.")
        err_msg = "No units provided for resource analysis"
        result.analysis_error = (
            f"{result.analysis_error}; {err_msg}" if result.analysis_error else err_msg
        )
        # Set unit_usage to empty list if no units provided
        result.unit_usage = []
    elif not HAS_DBUS:
        log.warning(
            "DBus bindings not installed, cannot perform per-unit resource analysis via cgroups."
        )
        err_msg = "DBus bindings not installed"
        result.analysis_error = (
            f"{result.analysis_error}; {err_msg}" if result.analysis_error else err_msg
        )
        result.unit_usage = []
    elif not dbus_manager:
        # Check if dbus is installed but manager connection failed earlier
        log.warning(
            "DBus manager connection unavailable, cannot perform per-unit resource analysis via cgroups."
        )
        err_msg = "DBus manager unavailable for cgroup lookup"
        result.analysis_error = (
            f"{result.analysis_error}; {err_msg}" if result.analysis_error else err_msg
        )
        result.unit_usage = []
    else:
        # Proceed only if units and dbus manager are available
        try:
            # Pass the provided units list and manager
            result.unit_usage = get_unit_resource_usage(units, dbus_manager)
        except Exception as e:
            log.exception("Unexpected error getting per-unit resource usage.")
            err_msg = f"Failed to get per-unit usage: {e}"
            result.analysis_error = (
                f"{result.analysis_error}; {err_msg}"
                if result.analysis_error
                else err_msg
            )
            # Ensure unit_usage is an empty list on error
            result.unit_usage = []

    # 3. Child Process Group Monitoring
    try:
        # Pass the provided units list and manager to PID helper
        service_pids = _get_service_pids(units, dbus_manager)
        if service_pids:
            result.child_process_groups = _scan_and_group_child_processes(service_pids)
        else:
            log.info("No active service PIDs found, skipping child process monitoring.")
    except Exception as e:
        log.exception("Error during child process group monitoring.")
        err_msg = f"Failed to monitor child process groups: {e}"
        result.analysis_error = (
            f"{result.analysis_error}; {err_msg}" if result.analysis_error else err_msg
        )

    # 4. Calculate Top N Consumers (Units)
    if result.unit_usage:
        try:
            # (Calculation logic remains the same)
            valid_cpu_units = [u for u in result.unit_usage if u.cpu_usage_nsec is not None]
            valid_mem_units = [
                u for u in result.unit_usage if u.memory_current_bytes is not None
            ]
            valid_io_units = [
                u
                for u in result.unit_usage
                if u.io_read_bytes is not None
                and u.io_write_bytes is not None
                and (u.io_read_bytes > 0 or u.io_write_bytes > 0)
            ]
            result.top_cpu_units = sorted(
                valid_cpu_units, key=lambda u: u.cpu_usage_nsec or 0, reverse=True
            )[:TOP_N_COUNT]
            result.top_memory_units = sorted(
                valid_mem_units,
                key=lambda u: u.memory_current_bytes or 0,
                reverse=True,
            )[:TOP_N_COUNT]
            result.top_io_units = sorted(
                valid_io_units,
                key=lambda u: (u.io_read_bytes or 0) + (u.io_write_bytes or 0),
                reverse=True,
            )[:TOP_N_COUNT]
            log.debug(
                f"Identified Top {TOP_N_COUNT} unit consumers: CPU={len(result.top_cpu_units)}, Mem={len(result.top_memory_units)}, IO={len(result.top_io_units)}"
            )
        except Exception as e:
            log.exception("Error calculating Top N unit consumers.")
            err_msg = f"Failed to calculate Top N units: {e}"
            result.analysis_error = (
                f"{result.analysis_error}; {err_msg}"
                if result.analysis_error
                else err_msg
            )
    else:
        # If unit_usage is empty or None, ensure Top N lists are also empty
        result.top_cpu_units = []
        result.top_memory_units = []
        result.top_io_units = []
        log.debug(
            "Skipping Top N unit calculation as per-unit usage data is unavailable."
        )

    log.info("Resource analysis finished.")
    return result
    