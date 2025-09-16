# src/sysdiag_analyzer/modules/dependencies.py
# -*- coding: utf-8 -*-

import logging
import collections
import re # Import re
from typing import List, Optional, Tuple, Dict, Any, Set

# Attempt to import DBus and helpers
try:
    import dbus
    import dbus.exceptions
    # Import fallback helper from health module
    from ..modules.health import _get_unit_properties_fallback
    HAS_DBUS = True
except ImportError:
    HAS_DBUS = False
    dbus = None
    # Define dummy fallback that returns None and tracks last stderr if needed for testing
    class DummyFallback:
        last_stderr = None
        def __call__(self, name):
            # Simulate failure for testing purposes if needed
            # In real scenario without dbus, this won't be called if HAS_DBUS is False
            return None
    _get_unit_properties_fallback = DummyFallback()

# Check for optional dependency networkx
try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False
    nx = None # Placeholder

from ..datatypes import (
    DependencyAnalysisResult,
    FailedUnitDependencyInfo,
    DependencyInfo,
    UnitHealthInfo, # Input type
    FullDependencyAnalysisResult
)
from ..utils import run_subprocess

log = logging.getLogger(__name__)
log_dep = logging.getLogger(__name__ + ".detail")
log_graph = logging.getLogger(__name__ + ".graph")

# --- Helper Functions ---

def _get_dependency_state(
    dep_name: str,
    dbus_manager: Optional[Any],
    # TODO (Optimization): Pass all_units dict for faster lookups?
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Fetches the load, active, and sub state for a given dependency unit name.
    Primarily uses the _get_unit_properties_fallback helper.
    Returns: (load_state, active_state, sub_state, error_message)
    """
    load_state, active_state, sub_state, error = None, None, None, None
    props: Optional[Dict[str, Any]] = None

    # Currently, we directly use the fallback for simplicity.
    # If DBus path is added later, it would go here.
    # if dbus_bus:
    #     # Complex logic to get path, then properties...
    #     pass

    # Fallback Path (or primary path if DBus failed/unavailable)
    log_dep.debug(f"Fetching state for dependency '{dep_name}' via fallback.")
    props = _get_unit_properties_fallback(dep_name) # Re-use from health module

    if props:
        load_state = props.get("LoadState")
        active_state = props.get("ActiveState")
        sub_state = props.get("SubState")
        log_dep.debug(f"State for '{dep_name}': L={load_state} A={active_state} S={sub_state}")
    else:
        # _get_unit_properties_fallback already logs warnings on failure.
        # If props is None, we cannot reliably determine the state.
        error = f"Failed to get properties for dependency '{dep_name}' via fallback."
        # No reliable way to synthesize 'not-found' here without more info from fallback.


    return load_state, active_state, sub_state, error


def _is_dependency_problematic(dep_info: DependencyInfo) -> bool:
    """Determines if a dependency's state is potentially problematic."""
    # Strong dependencies: Requires, ConsistsOf, BindsTo, Requisite, PartOf
    # Note: 'Unknown' type from --plain output is treated cautiously (like a strong dep)
    strong_dep_types = ["Requires", "ConsistsOf", "BindsTo", "Requisite", "PartOf", "Unknown"]
    if dep_info.type in strong_dep_types:
        # Failed or inactive/dead are problems for strong requirements
        # Also consider 'not-found' as problematic for strong deps (load state is None or 'not-found')
        if dep_info.current_active_state in ["failed", "inactive"] or \
           dep_info.current_sub_state == "dead" or \
           dep_info.current_load_state == "not-found" or \
           dep_info.current_load_state is None: # Treat inability to get state as problematic for strong deps
            log_dep.debug(f"Problematic strong/unknown dependency: {dep_info.name} (Type: {dep_info.type}, State: {dep_info.current_load_state}/{dep_info.current_active_state}/{dep_info.current_sub_state})")
            return True
    elif dep_info.type == "Wants": # Weaker dependencies
        # Only consider it problematic if it actually failed
        if dep_info.current_active_state == "failed":
            log_dep.debug(f"Problematic weak dependency: {dep_info.name} (State: failed)")
            return True
    # Before/After dependencies primarily affect ordering, less likely to be the *cause* of failure state itself.
    # Could add checks here if needed (e.g., if an 'After' unit is running but the main unit failed).
    return False

def analyze_dependencies(
    failed_units: List[UnitHealthInfo],
    dbus_manager: Optional[Any]
) -> DependencyAnalysisResult:
    """
    Analyzes dependencies for a list of failed units.
    """
    log.info(f"Starting dependency analysis for {len(failed_units)} failed units...")
    result = DependencyAnalysisResult()

    if not failed_units:
        log.debug("No failed units provided, skipping dependency analysis.")
        return result

    dbus_bus = getattr(dbus_manager, 'bus', None) if dbus_manager and HAS_DBUS else None
    if not dbus_bus:
        log.warning("DBus unavailable or manager invalid, dependency analysis will rely solely on 'systemctl show' fallback.")

    # Dependency property names to check (systemd v245+)
    # Source: systemd.unit(5) man page
    dep_prop_keys = [
        # Requirements Dependencies
        "Requires", "Requisite", "Wants", "BindsTo",
        # Ordering Dependencies
        "Before", "After",
        # Other
        "PartOf", "ConsistsOf"
        # Conflicts= is usually not checked when analyzing failure causes
    ]

    for failed_unit in failed_units:
        unit_name = failed_unit.name
        log.debug(f"Analyzing dependencies for failed unit: {unit_name}")
        unit_dep_info = FailedUnitDependencyInfo(unit_name=unit_name)
        dep_map: Dict[str, str] = {} # dep_name -> type
        error_this_unit: Optional[str] = None
        props: Optional[Dict[str, Any]] = None

        # 1. Get Dependency Names (DBus or Fallback)
        # Simplified: Use fallback directly for now to avoid complex DBus logic here
        # TODO: Add DBus path for getting properties if performance requires it
        props = _get_unit_properties_fallback(unit_name)

        if props is None:
            # _get_unit_properties_fallback already logged the reason
            error_this_unit = f"Failed to get properties for {unit_name} to check dependencies."
            unit_dep_info.error = error_this_unit
            result.failed_unit_dependencies.append(unit_dep_info)
            continue # Skip to next failed unit

        # Parse dependency names from properties
        for prop_key in dep_prop_keys:
            dep_list_str = props.get(prop_key, "")
            if dep_list_str:
                # systemctl show output is space-separated
                for dep_name in dep_list_str.split():
                    if dep_name and dep_name not in dep_map: # Avoid duplicates if listed in multiple props
                        dep_map[dep_name] = prop_key # Store the type (Requires, Wants, etc.)

        if not dep_map:
            log.debug(f"No dependencies found listed for failed unit {unit_name}.")
            # Still add the entry, just with an empty list
            result.failed_unit_dependencies.append(unit_dep_info)
            continue

        log.debug(f"Found {len(dep_map)} potential dependencies for {unit_name}: {list(dep_map.keys())}")

        # 2. Get State for Each Dependency
        for dep_name, dep_type in dep_map.items():
            load, active, sub, dep_error = _get_dependency_state(dep_name, dbus_manager)
            # Log the error here if _get_dependency_state reported one
            if dep_error:
                log.warning(f"Error getting state for dependency '{dep_name}' of '{unit_name}': {dep_error}")

            dep_info = DependencyInfo(
                name=dep_name,
                type=dep_type,
                current_load_state=load,
                current_active_state=active,
                current_sub_state=sub
            )
            dep_info.is_problematic = _is_dependency_problematic(dep_info)
            unit_dep_info.dependencies.append(dep_info)

        # Sort dependencies alphabetically for consistent output
        unit_dep_info.dependencies.sort(key=lambda d: d.name)
        result.failed_unit_dependencies.append(unit_dep_info)

    log.info(f"Dependency analysis finished for {len(failed_units)} failed units.")
    return result

# Define TREE_CHARS at module level for use in parsing
TREE_CHARS = "●○├└│─" # Characters used for tree drawing

def _fetch_all_dependencies_fallback() -> Tuple[Optional[Dict[str, Dict[str, List[str]]]], Optional[str]]:
    """
    Fetches all dependencies using 'systemctl list-dependencies --all'.
    Parses the output which includes tree characters.
    Returns a dict mapping unit -> {'Requires': [deps]} and an optional error message.
    NOTE: Assumes 'Requires' type as the format doesn't specify.
    """
    log_graph.info("Fetching all dependencies via 'systemctl list-dependencies --all'...")
    # REMOVED --plain flag to get the richer tree output
    command = ["systemctl", "list-dependencies", "--all", "--no-legend", "--no-pager"]
    success, stdout, stderr = run_subprocess(command)

    if not success:
        err = f"systemctl list-dependencies command failed: {stderr or stdout or 'Unknown error'}"
        log_graph.error(err)
        return None, err

    stdout_snippet = stdout[:1000].strip() + ('...' if len(stdout) > 1000 else '')
    log_graph.debug(f"Raw systemctl list-dependencies output (snippet):\n---\n{stdout_snippet}\n---")

    # Structure: { unit_name: { "Requires": [...] } } - Assume 'Requires'
    all_deps: Dict[str, Dict[str, List[str]]] = collections.defaultdict(lambda: collections.defaultdict(list))
    all_units: Set[str] = set()
    current_main_unit: Optional[str] = None
    line_count = 0
    parsed_dep_count = 0

    for line_num, line in enumerate(stdout.splitlines()):
        line_count += 1
        line_stripped = line.strip()

        if not line_stripped:
            log_graph.debug(f"Line {line_num + 1}: Skipping blank line.")
            continue

        # Match the prefix including optional ●/○ and tree chars
        # Allow for spaces between ● and tree chars
        prefix_match = re.match(r"^(\s*(?:[●○]\s*)?[├└│\s]*)", line)
        prefix = prefix_match.group(1) if prefix_match else ""

        # Extract unit name after the prefix
        unit_name = line[len(prefix):].strip()

        # If unit name is empty after stripping prefix, skip
        if not unit_name:
            log_graph.debug(f"Line {line_num + 1}: Skipping line with no unit name after prefix '{prefix}': '{line}'")
            continue

        # Determine if it's a main unit or dependency based on prefix content
        # Main units usually have no prefix or just whitespace/dot
        is_dependency = any(c in prefix for c in TREE_CHARS if c not in ' ')

        if not is_dependency:
            current_main_unit = unit_name
            all_units.add(current_main_unit)
            # Ensure the unit exists in the dict even if it has no deps listed below
            if current_main_unit not in all_deps:
                 all_deps[current_main_unit] = collections.defaultdict(list)
            log_graph.debug(f"Line {line_num + 1}: Identified main unit: '{current_main_unit}'")
        elif is_dependency:
            if current_main_unit is None:
                log_graph.warning(f"Line {line_num + 1}: Skipping dependency line found before any main unit identified: '{unit_name}'")
                continue

            # Assume 'Requires' type for simplicity from this output format
            dep_type = "Requires" # Default assumption
            unit_name = unit_name.lstrip(TREE_CHARS + ' ')

            if not unit_name:
                 log_graph.debug(f"Line {line_num + 1}: Skipping dependency line - empty unit name after stripping: '{line}'")
                 continue

            all_deps[current_main_unit][dep_type].append(unit_name)
            all_units.add(unit_name) # Ensure dependency is also added as a node
            parsed_dep_count += 1
            log_graph.debug(f"Line {line_num + 1}: Parsed dependency '{unit_name}' (Type: {dep_type}) for unit '{current_main_unit}'")

    log_graph.info(f"Processed {line_count} lines from systemctl output.")
    units_with_deps_count = len([u for u, d in all_deps.items() if any(d.values())])
    total_unique_units = len(all_units)
    log_graph.info(f"Found {total_unique_units} unique units in total.")
    log_graph.info(f"Parsed {parsed_dep_count} dependency relationships for {units_with_deps_count} units.")

    if parsed_dep_count == 0 and stdout.strip():
        log_graph.warning("Parsing logic identified units but found zero dependency relationships in the command output. The format might be unexpected or dependencies are missing.")

    final_deps = {unit: dict(deps) for unit, deps in all_deps.items()}
    return final_deps, None


def _build_dependency_graph(
    dep_data: Dict[str, Dict[str, List[str]]]
) -> Tuple[Optional['nx.DiGraph'], Optional[str]]:
    """Builds a NetworkX DiGraph from the dependency data."""
    if not HAS_NETWORKX or nx is None:
        # Ensure tuple return even if networkx not installed
        return None, "networkx library is not installed."

    log_graph.info("Building dependency graph...")
    graph = nx.DiGraph() # Initialize graph here
    try:
        all_unit_names: Set[str] = set(dep_data.keys())

        # Add nodes first
        for unit, deps_by_type in dep_data.items():
            for dep_list in deps_by_type.values():
                all_unit_names.update(dep_list)
        graph.add_nodes_from(all_unit_names)
        log_graph.debug(f"Added {len(all_unit_names)} nodes to the graph.")

        # Add edges
        edge_count = 0
        for unit, deps_by_type in dep_data.items():
            for dep_type, dep_list in deps_by_type.items():
                for dependency in dep_list:
                    if dependency in graph: # Ensure target node exists
                        # Edge direction: unit -> dependency (unit depends on dependency)
                        graph.add_edge(unit, dependency, type=dep_type)
                        edge_count += 1
                    else:
                        log_graph.warning(f"Dependency target '{dependency}' for unit '{unit}' not found in node list, skipping edge.")

        log_graph.info(f"Built graph with {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges.")
        return graph, None
    except Exception as e:
        log_graph.exception(f"Error building dependency graph: {e}")
        # Ensure tuple return on error
        return graph, f"Error building graph: {e}" # Return partially built graph and error

def _find_cycles(graph: 'nx.DiGraph') -> List[List[str]]:
    """Finds simple cycles in the dependency graph."""
    if not HAS_NETWORKX or nx is None:
        log_graph.warning("Cannot find cycles, networkx is not available.")
        return []
    try:
        log_graph.info("Detecting cycles in the dependency graph...")
        # Note: simple_cycles yields lists of nodes in the cycle
        cycles = list(nx.simple_cycles(graph))
        log_graph.info(f"Found {len(cycles)} simple cycles.")
        # Log cycles if debugging is enabled
        if cycles and log_graph.isEnabledFor(logging.DEBUG):
             for i, cycle in enumerate(cycles):
                  log_graph.debug(f"  Cycle {i+1}: {' -> '.join(cycle)} -> {cycle[0]}")
        return cycles
    except Exception as e:
        log_graph.exception(f"Error during cycle detection: {e}")
        return [] # Return empty list on error

def analyze_full_dependency_graph() -> FullDependencyAnalysisResult:
    """
    Performs full dependency graph analysis, focusing on cycle detection.
    """
    log.info("Starting full dependency graph analysis...")
    result = FullDependencyAnalysisResult()

    if not HAS_NETWORKX:
        result.analysis_error = "Optional dependency 'networkx' is not installed. Skipping full graph analysis."
        log.warning(result.analysis_error)
        return result

    # 1. Fetch Dependencies
    dep_data, fetch_err = _fetch_all_dependencies_fallback()
    if fetch_err:
        result.dependency_fetch_error = fetch_err
        result.analysis_error = "Failed to fetch full dependency list."
        log.error(f"{result.analysis_error}: {fetch_err}")
        return result

    if dep_data is None:
         result.analysis_error = "Dependency data is None after fetch attempt."
         log.error(result.analysis_error)
         return result

    if not dep_data:
         log.info("No dependencies found after fetching. Proceeding with empty graph.")

    # 2. Build Graph
    graph, build_err = _build_dependency_graph(dep_data)
    if build_err:
        result.graph_build_error = build_err
        result.analysis_error = "Failed to build dependency graph."
        log.error(f"{result.analysis_error}: {build_err}")
        # If graph build failed, graph might be None or partially built
        # We cannot proceed to find cycles.
        return result
    if graph is None: # Should only happen if networkx check failed earlier or build_err is set
        result.analysis_error = result.analysis_error or "Dependency graph object is None after build attempt (unexpected)."
        log.error(result.analysis_error)
        return result

    # 3. Find Cycles
    result.detected_cycles = _find_cycles(graph)

    log.info(f"Full dependency graph analysis finished. Found {len(result.detected_cycles)} cycles.")
    return result
