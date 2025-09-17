# src/sysdiag_analyzer/unit_analyzer.py
# -*- coding: utf-8 -*-

import logging
from typing import Optional, Any, Dict

from .datatypes import (
    SingleUnitReport,
    UnitHealthInfo,
    UnitResourceUsage,
    FailedUnitDependencyInfo,
    DependencyInfo,
)
from .modules.health import (
    _get_unit_properties_dbus,
    _get_unit_properties_fallback,
    _get_unit_logs,
    HAS_DBUS,
)
from .modules.resources import get_unit_resource_usage
from .modules.dependencies import _get_dependency_state, _is_dependency_problematic

log = logging.getLogger(__name__)


def _analyze_single_unit_dependencies(
    unit_name: str, unit_props: dict, dbus_manager: Optional[Any]
) -> FailedUnitDependencyInfo:
    """Analyzes dependencies for a single unit, regardless of its state."""
    info = FailedUnitDependencyInfo(unit_name=unit_name)
    dep_prop_keys = [
        "Requires",
        "Requisite",
        "Wants",
        "BindsTo",
        "Before",
        "After",
        "PartOf",
        "ConsistsOf",
    ]
    dep_map: Dict[str, str] = {}

    for prop_key in dep_prop_keys:
        dep_list_str = unit_props.get(prop_key, "")
        if dep_list_str:
            for dep_name in dep_list_str.split():
                if dep_name and dep_name not in dep_map:
                    dep_map[dep_name] = prop_key

    if not dep_map:
        log.debug(f"No dependencies found listed for unit {unit_name}.")
        return info

    for dep_name, dep_type in dep_map.items():
        load, active, sub, dep_error = _get_dependency_state(dep_name, dbus_manager)
        if dep_error:
            log.warning(
                f"Error getting state for dependency '{dep_name}' of '{unit_name}': {dep_error}"
            )

        dep_info = DependencyInfo(
            name=dep_name,
            type=dep_type,
            current_load_state=load,
            current_active_state=active,
            current_sub_state=sub,
        )
        dep_info.is_problematic = _is_dependency_problematic(dep_info)
        info.dependencies.append(dep_info)

    info.dependencies.sort(key=lambda d: d.name)
    return info


def run_single_unit_analysis(
    unit_name: str, dbus_manager: Optional[Any]
) -> SingleUnitReport:
    """
    Orchestrates a focused analysis of a single systemd unit.
    """
    log.info(f"Starting focused analysis for unit: {unit_name}")
    report = SingleUnitReport()

    unit_props: Optional[dict] = None
    unit_path: Optional[str] = None
    dbus_bus = getattr(dbus_manager, "bus", None) if dbus_manager and HAS_DBUS else None

    # 1. Get Unit Properties
    try:
        if dbus_manager:
            unit_path = dbus_manager.GetUnit(unit_name)
        if dbus_bus and unit_path:
            unit_props = _get_unit_properties_dbus(dbus_bus, unit_path)
    except Exception:
        log.debug(f"Could not get unit path for {unit_name} via DBus, using fallback.")

    if unit_props is None:
        unit_props = _get_unit_properties_fallback(unit_name)

    if unit_props is None:
        report.analysis_error = f"Unit '{unit_name}' not found or properties could not be fetched."
        log.error(report.analysis_error)
        return report

    # 2. Populate UnitHealthInfo
    unit_info = UnitHealthInfo(
        name=unit_props.get("Id", unit_name),
        load_state=unit_props.get("LoadState"),
        active_state=unit_props.get("ActiveState"),
        sub_state=unit_props.get("SubState"),
        description=unit_props.get("Description"),
        path=unit_path,
        details=unit_props,
    )
    report.unit_info = unit_info

    # 3. Get Logs
    try:
        unit_info.recent_logs = _get_unit_logs(unit_name, num_lines=50)
    except Exception as e:
        log.error(f"Failed to fetch logs for {unit_name}: {e}")
        unit_info.recent_logs = [f"[Error fetching logs: {e}]"]

    # 4. Get Resource Usage
    try:
        resource_results = get_unit_resource_usage([unit_info], dbus_manager)
        if resource_results:
            report.resource_usage = resource_results[0]
    except Exception as e:
        log.error(f"Failed to get resource usage for {unit_name}: {e}")
        if report.resource_usage is None:
            report.resource_usage = UnitResourceUsage(name=unit_name)
        report.resource_usage.error = f"Analysis failed: {e}"

    # 5. Get Dependencies
    try:
        report.dependency_info = _analyze_single_unit_dependencies(
            unit_name, unit_props, dbus_manager
        )
    except Exception as e:
        log.error(f"Failed to analyze dependencies for {unit_name}: {e}")
        if report.dependency_info:
            report.dependency_info.error = f"Analysis failed: {e}"

    log.info(f"Focused analysis for {unit_name} complete.")
    return report
