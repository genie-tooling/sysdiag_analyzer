# src/sysdiag_analyzer/utils.py
import logging
import json
import re
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any

import subprocess

from .datatypes import UnitHealthInfo

log = logging.getLogger(__name__)

# Regex to find systemd-escaped device paths in unit names.
DEVICE_UNIT_PATTERN = re.compile(
    r"(?P<prefix>.*@)?"
    r"(?P<device_path>dev-[\w\\x2d-]+)"
    r"(?P<suffix>\.(?:device|swap|target|service|mount))"
)


def run_subprocess(command: List[str]) -> Tuple[bool, str, str]:
    """
    Runs a subprocess synchronously and returns success status, stdout, and stderr.

    Args:
        command: A list representing the command and its arguments.

    Returns:
        A tuple containing:
        - bool: True if the command executed successfully (exit code 0), False otherwise.
        - str: The standard output decoded as UTF-8.
        - str: The standard error decoded as UTF-8.
    """
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,  # Decode stdout/stderr as text
            check=False,  # Don't raise exception on non-zero exit code
        )
        if process.returncode == 0:
            log.debug(f"Command '{' '.join(command)}' succeeded.")
            return True, process.stdout.strip(), process.stderr.strip()
        else:
            log.warning(
                f"Command '{' '.join(command)}' failed with exit code {process.returncode}."
            )
            log.debug(f"Stderr: {process.stderr.strip()}")
            return False, process.stdout.strip(), process.stderr.strip()

    except FileNotFoundError:
        log.error(f"Command not found: {command[0]}. Is it installed and in PATH?")
        return False, "", f"Command not found: {command[0]}"
    except Exception as e:
        log.exception(
            f"An unexpected error occurred running command '{' '.join(command)}': {e}"
        )
        return False, "", f"Unexpected error: {e}"


_cached_boot_id: Optional[str] = None


def get_boot_id() -> Optional[str]:
    """
    Gets the current system boot ID.
    Prefers journalctl, falls back to /proc/sys/kernel/random/boot_id.
    Caches the result for subsequent calls within the same run.
    """
    global _cached_boot_id
    if _cached_boot_id:
        return _cached_boot_id

    # Try journalctl first
    cmd = ["journalctl", "--list-boots", "-n", "1", "--no-pager", "--output=json"]
    try:
        success, stdout, stderr = run_subprocess(cmd)
        if success and stdout.strip():
            last_valid_entry = None
            for line in stdout.strip().splitlines():
                try:
                    entry = json.loads(line)
                    if isinstance(entry, dict) and "boot_id" in entry:
                        last_valid_entry = entry  # Keep track of the last valid entry
                except json.JSONDecodeError as e:
                    log.warning(
                        f"Failed to parse JSON line from journalctl --list-boots: {e}. Line: '{line[:100]}...'"
                    )
                    # Continue to next line if one line fails

            if last_valid_entry:
                boot_id = last_valid_entry.get("boot_id")
                if boot_id:
                    log.debug(f"Retrieved boot ID via journalctl: {boot_id}")
                    _cached_boot_id = boot_id
                    return boot_id
                else:
                    # This case should be unlikely if "boot_id" was checked before assigning last_valid_entry
                    log.warning(
                        "Last valid journalctl boot entry unexpectedly missing 'boot_id'."
                    )
            else:
                log.warning(
                    "Could not find any valid boot entry with 'boot_id' in journalctl output."
                )

        else:
            # Log failure only if stdout was empty or command failed
            if not success:
                log.warning(
                    f"journalctl --list-boots command failed. Stderr: {stderr}"
                )
            elif not stdout.strip():
                log.warning("journalctl --list-boots output was empty.")

    except Exception as e:
        # Catch other potential errors during subprocess or parsing
        log.error(f"Error getting boot ID via journalctl: {e}", exc_info=True)

    # Final fallback or if errors occurred
    log.debug("Falling back to /proc/sys/kernel/random/boot_id for boot ID.")
    try:
        proc_path = Path("/proc/sys/kernel/random/boot_id")
        if proc_path.is_file():
            boot_id_proc = proc_path.read_text().strip().replace("-", "")
            if boot_id_proc:
                # Use warning level here as it's a fallback
                log.warning(
                    f"Using boot ID from /proc/sys/kernel/random/boot_id: {boot_id_proc}"
                )
                _cached_boot_id = boot_id_proc
                return boot_id_proc
            else:
                log.warning("/proc/sys/kernel/random/boot_id was empty.")
        else:
            log.warning("/proc/sys/kernel/random/boot_id not found.")
    except Exception as e:
        log.error(
            f"Could not read boot ID from /proc/sys/kernel/random/boot_id: {e}",
            exc_info=True,
        )

    log.error("Could not determine boot ID from journalctl or /proc.")
    return None


def _resolve_unit_to_canonical_device_name(unit_name: str) -> Optional[str]:
    """
    If the unit name represents a device symlink (e.g., by-uuid), resolve it
    to its canonical device name (e.g., 'dev-sda1.device') using systemd-escape
    and Path.resolve(). Returns the new name or None if no change is needed.
    """
    match = DEVICE_UNIT_PATTERN.fullmatch(unit_name)
    if not match:
        return None

    groups = match.groupdict()
    prefix = groups.get("prefix") or ""
    escaped_device_path = groups["device_path"]
    suffix = groups["suffix"]

    # Use systemd-escape --unescape for a robust conversion from unit name to path
    success, unescaped_path, stderr = run_subprocess(
        ["systemd-escape", "--unescape", "--path", escaped_device_path]
    )

    if not success or not unescaped_path:
        log.debug(f"systemd-escape failed for '{escaped_device_path}': {stderr}")
        return None

    try:
        # Now that we have a valid filesystem path, resolve the symlink
        resolved_path = Path(unescaped_path).resolve()

        # Reconstruct the canonical systemd unit name from the resolved path
        # e.g., resolved_path.name -> 'nvme0n1p1'
        # suffix -> '.device'
        # result -> 'dev-nvme0n1p1.device'
        canonical_device_name = f"dev-{resolved_path.name}"
        canonical_unit_name = f"{prefix}{canonical_device_name}{suffix}"

        # If resolution didn't change the name, it's not a symlink we need to handle
        if canonical_unit_name == unit_name:
            return None

        return canonical_unit_name
    except FileNotFoundError:
        # This is expected for devices that are no longer present
        log.debug(f"Path '{unescaped_path}' (from '{unit_name}') not found for resolution.")
        return None
    except Exception as e:
        log.warning(f"Unexpected error resolving device unit {unit_name}: {e}")
        return None


def deduplicate_report_data_in_memory(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Takes a loaded report dictionary, resolves device symlinks in all relevant
    sections, merges metrics for duplicates, and returns the cleaned report.
    This is a critical step for making historical data consistent.
    """
    # Resource Analysis: unit_usage, top_*_units
    res_analysis = report.get("resource_analysis")
    if res_analysis and isinstance(res_analysis.get("unit_usage"), list):
        merged_usage: Dict[str, Dict[str, Any]] = {}
        for unit_res in res_analysis["unit_usage"]:
            if not isinstance(unit_res, dict) or "name" not in unit_res:
                continue
            original_name = unit_res["name"]
            canonical_name = (
                _resolve_unit_to_canonical_device_name(original_name) or original_name
            )
            if canonical_name not in merged_usage:
                unit_res["name"] = canonical_name
                merged_usage[canonical_name] = unit_res
            else:
                existing = merged_usage[canonical_name]
                for key, value in unit_res.items():
                    if isinstance(value, (int, float)):
                        existing[key] = (existing.get(key) or 0) + value
        res_analysis["unit_usage"] = list(merged_usage.values())

    # Health Analysis: failed_units, flapping_units, etc.
    health_analysis = report.get("health_analysis")
    if health_analysis:
        for key in [
            "failed_units",
            "flapping_units",
            "problematic_sockets",
            "problematic_timers",
        ]:
            if isinstance(health_analysis.get(key), list):
                processed_units: Dict[str, Dict[str, Any]] = {}
                for unit_health in health_analysis[key]:
                    if not isinstance(unit_health, dict) or "name" not in unit_health:
                        continue
                    original_name = unit_health["name"]
                    canonical_name = (
                        _resolve_unit_to_canonical_device_name(original_name)
                        or original_name
                    )
                    if canonical_name not in processed_units:
                        unit_health["name"] = canonical_name
                        processed_units[canonical_name] = unit_health
                health_analysis[key] = list(processed_units.values())

    # Boot Analysis: blame, critical_chain
    boot_analysis = report.get("boot_analysis")
    if boot_analysis:
        for key in ["blame", "critical_chain"]:
            if isinstance(boot_analysis.get(key), list):
                for item in boot_analysis[key]:
                    if isinstance(item, dict) and "unit" in item:
                        original_name = item["unit"]
                        item["unit"] = (
                            _resolve_unit_to_canonical_device_name(original_name)
                            or original_name
                        )
    return report


def deduplicate_device_units(units: List[UnitHealthInfo]) -> List[UnitHealthInfo]:
    """
    Deduplicates device-related units by resolving their symlinks to canonical paths.
    It updates unit names to their canonical form and removes duplicates.
    """
    log.info("Deduplicating device-related units by resolving canonical paths...")
    canonical_units: Dict[str, UnitHealthInfo] = {}
    remap_count = 0

    for unit in units:
        original_name = unit.name
        canonical_name = _resolve_unit_to_canonical_device_name(original_name)
        final_name = canonical_name or original_name
        if canonical_name:
            log.debug(f"Resolved '{original_name}' -> '{canonical_name}'")
            unit.name = canonical_name
            remap_count += 1
        if final_name not in canonical_units:
            canonical_units[final_name] = unit
        else:
            log.debug(
                f"Skipping duplicate unit '{original_name}' which resolves to already processed canonical name '{final_name}'."
            )
    if remap_count > 0:
        log.info(f"Resolved {remap_count} symlinked device unit names.")

    final_unit_list = list(canonical_units.values())
    if len(final_unit_list) < len(units):
        log.info(
            f"Unit list size reduced from {len(units)} to {len(final_unit_list)} after deduplication."
        )
    else:
        log.info("No duplicate device units were found.")
    return final_unit_list