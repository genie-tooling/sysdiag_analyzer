import logging
import json
from typing import List, Optional, Tuple, Dict, Any

try:
    import dbus
    import dbus.exceptions # Import exceptions submodule
    HAS_DBUS = True
    log_dbus = logging.getLogger(__name__ + ".dbus") # Specific logger for dbus details
except ImportError:
    HAS_DBUS = False
    dbus = None # Placeholder

# Local imports
from ..datatypes import HealthAnalysisResult, UnitHealthInfo
from ..utils import run_subprocess
# Reuse journal helpers from boot module if possible and safe
try:
    # Import updated flags and functions from boot
    from .boot import (
        _parse_journal_entry_time,
        HAS_NATIVE_JOURNAL,
        HAS_CYSYSTEMD,
        HAS_PYTHON_SYSTEMD,
        JournalReader,
        JournalOpenMode,
        Rule,
        journal # Old binding for compatibility if needed
    )
except ImportError as e:
    # Fallback if boot module structure changes or imports fail
    log_boot_import = logging.getLogger(__name__)
    log_boot_import.error(f"Could not import journal helpers from boot module: {e}. Native log fetching disabled.", exc_info=True)
    HAS_NATIVE_JOURNAL = False
    HAS_CYSYSTEMD = False
    HAS_PYTHON_SYSTEMD = False
    # Define dummy functions/classes if needed, or rely on fallback logic
    def _parse_journal_entry_time(entry):
        return None
    class JournalReader:
        pass
    class JournalOpenMode:
        SYSTEM = None # Add dummy attributes if accessed before check
        pass
    class Rule:
        pass
    class journal:
        @staticmethod
        def Reader():
            raise NotImplementedError

log = logging.getLogger(__name__)

# --- Constants ---
FLAPPING_RESTART_THRESHOLD = 3 # Number of restarts considered flapping

# --- DBus Helper Functions ---
def _get_systemd_manager_interface() -> Optional[Any]:
    """Connects to DBus and returns the systemd manager interface."""
    if not HAS_DBUS:
        log.debug("DBus bindings not available.")
        return None
    try:
        if dbus is None:
             raise ImportError("dbus module was not imported successfully")
        bus = dbus.SystemBus()
        systemd_object = bus.get_object('org.freedesktop.systemd1', '/org/freedesktop/systemd1')
        manager_interface = dbus.Interface(systemd_object, 'org.freedesktop.systemd1.Manager')
        manager_interface.bus = bus
        log.debug("Successfully connected to systemd manager via DBus.")
        return manager_interface
    except dbus.exceptions.DBusException as e:
        log.warning(f"Failed to connect to systemd manager via DBus: {e}")
        return None
    except Exception as e:
        log.error(f"Unexpected error connecting to DBus: {e}")
        return None

def _dbus_to_python(val: Any) -> Any:
    """Converts common DBus types to Python types for serialization/use."""
    if HAS_DBUS and dbus:
        if isinstance(val, (dbus.String, dbus.ObjectPath)):
            return str(val)
        if isinstance(val, (dbus.Int32, dbus.UInt32, dbus.Int64, dbus.UInt64, dbus.Byte)):
            return int(val)
        if isinstance(val, dbus.Double):
            return float(val)
        if isinstance(val, dbus.Boolean):
            return bool(val)
        if isinstance(val, (dbus.Array, list)):
            return [_dbus_to_python(x) for x in val]
        if isinstance(val, (dbus.Dictionary, dict)):
            return {str(k): _dbus_to_python(v) for k, v in val.items()}
    return val

def _get_unit_properties_dbus(bus: 'dbus.SystemBus', unit_path: str) -> Optional[Dict[str, Any]]:
    """Gets all properties for a specific unit via DBus."""
    # (Logic remains the same)
    if not unit_path or not bus or not HAS_DBUS or not dbus:
        return None
    log_dbus.debug(f"Fetching DBus properties for path: {unit_path}")
    try:
        unit_object = bus.get_object('org.freedesktop.systemd1', unit_path)
        properties_interface = dbus.Interface(unit_object, 'org.freedesktop.DBus.Properties')
        interfaces_to_fetch = [
            'org.freedesktop.systemd1.Unit', 'org.freedesktop.systemd1.Service',
            'org.freedesktop.systemd1.Socket', 'org.freedesktop.systemd1.Timer',
            'org.freedesktop.systemd1.Mount', 'org.freedesktop.systemd1.Device',
            'org.freedesktop.systemd1.Scope', 'org.freedesktop.systemd1.Slice',
        ]
        all_props = {}
        for iface_name in interfaces_to_fetch:
            try:
                log_dbus.debug(f"Calling Properties.GetAll('{iface_name}') for {unit_path}...")
                props = properties_interface.GetAll(iface_name)
                py_props = {str(k): _dbus_to_python(v) for k, v in props.items()}
                all_props.update(py_props)
                log_dbus.debug(f"Fetched {len(py_props)} props from {iface_name} for {unit_path}. Keys: {list(py_props.keys())}")
            except dbus.exceptions.DBusException as e:
                dbus_error_name = getattr(e, '_dbus_error_name', 'UnknownDBusError')
                if "Unknown interface" in str(e) or "Unknown method GetAll" in str(e) or \
                   "does not exist" in str(e) or "org.freedesktop.DBus.Error.UnknownInterface" in dbus_error_name or \
                   "org.freedesktop.DBus.Error.UnknownMethod" in dbus_error_name:
                     log_dbus.debug(f"Interface {iface_name} not found or GetAll failed for {unit_path} (expected for some types).")
                else:
                     log_dbus.warning(f"DBus error getting properties from {iface_name} for {unit_path}: {e}")
        if not all_props:
             log_dbus.warning(f"No properties successfully fetched for {unit_path} via DBus GetAll.")
             return None
        log_dbus.debug(f"Returning {len(all_props)} processed properties for {unit_path}")
        return all_props
    except dbus.exceptions.DBusException as e:
        log_dbus.warning(f"DBus error processing properties for {unit_path}: {e}")
        return None
    except Exception as e:
        log.error(f"Unexpected error getting DBus properties for {unit_path}: {e}", exc_info=True)
        return None

# --- Unit Fetching Functions (Used by main.py now) ---
def _get_all_units_dbus(manager: Any) -> Tuple[List[UnitHealthInfo], Optional[str]]:
    """Fetches all unit info using systemd Manager.ListUnits() via DBus."""
    # (Logic remains the same)
    units = []
    error = None
    log.debug("Fetching units via DBus ListUnits...")
    try:
        if not manager or not hasattr(manager, 'ListUnits'):
             raise ValueError("Invalid DBus manager object provided.")
        raw_units = manager.ListUnits()
        log.debug(f"DBus ListUnits returned {len(raw_units)} units.")
        for u in raw_units:
            if isinstance(u, (list, tuple)) and len(u) >= 7:
                unit_info = UnitHealthInfo(
                    name=str(u[0]), description=str(u[1]), load_state=str(u[2]),
                    active_state=str(u[3]), sub_state=str(u[4]), path=str(u[6])
                )
                units.append(unit_info)
            else:
                 log.warning(f"Skipping DBus unit entry with unexpected structure: {u!r}")
    except dbus.exceptions.DBusException as e:
        log.error(f"DBus error calling ListUnits: {e}")
        error = f"DBus error calling ListUnits: {e}"
    except Exception as e:
        log.error(f"Unexpected error processing DBus ListUnits results: {e}", exc_info=True)
        error = f"Unexpected error processing DBus ListUnits: {e}"
    log.debug(f"DBus fetch resulted in {len(units)} units, error: {error}")
    return units, error

def _get_all_units_json() -> Tuple[List[UnitHealthInfo], Optional[str]]:
    """Fetches all unit info using 'systemctl list-units --all --output=json'."""
    # (Logic remains the same)
    units = []
    error = None
    log.debug("Fetching units via systemctl list-units JSON fallback...")
    command = ["systemctl", "list-units", "--all", "--output=json", "--no-legend", "--no-pager"]
    log.info(f"Executing fallback command: {' '.join(command)}")
    success, stdout, stderr = run_subprocess(command)
    if not success:
        error_detail = stderr.strip() or stdout.strip() or "Unknown error"
        error = f"systemctl list-units command failed: {error_detail}"
        log.error(error)
        return units, error
    log.debug(f"systemctl list-units stdout (length {len(stdout)}):\n---\n{stdout[:1000]}{'...' if len(stdout)>1000 else ''}\n---")
    if stderr:
        log.debug(f"systemctl list-units stderr:\n---\n{stderr}\n---")
    try:
        stdout_stripped = stdout.strip()
        if not stdout_stripped:
             log.warning("systemctl list-units JSON output was empty or whitespace only.")
             return units, None
        raw_units = json.loads(stdout_stripped)
        log.debug(f"Successfully parsed JSON output. Type: {type(raw_units)}, Length: {len(raw_units) if isinstance(raw_units, list) else 'N/A'}")
        if not isinstance(raw_units, list):
             error = f"Expected a list of units from systemctl JSON output, got {type(raw_units)}"
             log.error(error)
             return units, error
        log.debug(f"Processing {len(raw_units)} units from systemctl JSON...")
        processed_count = 0
        skipped_count = 0
        for u in raw_units:
             if not isinstance(u, dict):
                  log.warning(f"Skipping non-dictionary item in systemctl JSON list: {u!r}")
                  skipped_count += 1
                  continue
             unit_name = u.get("unit")
             if not unit_name:
                  log.warning(f"Skipping systemctl unit entry missing 'unit' field: {u}")
                  skipped_count += 1
                  continue
             units.append(UnitHealthInfo(
                 name=str(unit_name), load_state=u.get("load"), active_state=u.get("active"),
                 sub_state=u.get("sub"), description=u.get("description"),
             ))
             processed_count +=1
        log.debug(f"Finished processing systemctl JSON: {processed_count} units added, {skipped_count} skipped.")
    except json.JSONDecodeError as e:
        error = f"Failed to parse systemctl JSON output: {e}. Output snippet: {stdout_stripped[:200]}..."
        log.error(error)
    except Exception as e:
        error = f"Unexpected error processing systemctl JSON output: {e}"
        log.error(error, exc_info=True)
    if not error and not units and isinstance(raw_units, list) and len(raw_units) > 0:
        log.warning(f"Parsed {len(raw_units)} entries from systemctl JSON, but none were added (e.g., all lacked 'unit' field?).")
    log.debug(f"systemctl JSON fetch resulted in {len(units)} units, error: {error}")
    return units, error

# --- Detail/Log Fetching Functions ---
def _get_unit_properties_fallback(unit_name: str) -> Optional[Dict[str, Any]]:
    """Gets unit properties using 'systemctl show <unit_name>'."""
    # (Logic remains the same)
    props = {}
    log.debug(f"Fetching properties for {unit_name} via systemctl show fallback...")
    command = ["systemctl", "show", unit_name, "--no-pager"]
    success, stdout, stderr = run_subprocess(command)
    if not success:
        error_detail = stderr.strip() or stdout.strip() or "Unknown error"
        if "Unit" in error_detail and ("not loaded" in error_detail or "not found" in error_detail):
             log.warning(f"Unit {unit_name} not found or not loaded via systemctl show.")
        else:
             log.warning(f"systemctl show command failed for {unit_name}: {error_detail}")
        return None
    for line in stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            props[key.strip()] = value.strip()
    log.debug(f"Fetched {len(props)} properties for {unit_name} via systemctl show.")
    return props

def _get_unit_logs(unit_name: str, num_lines: int = 20) -> List[str]:
    """Fetches recent log lines for a specific unit."""
    # (Logic remains the same)
    logs = []
    error_msg = None
    log.debug(f"Fetching last {num_lines} logs for unit: {unit_name} (Native Preferred: {HAS_NATIVE_JOURNAL})")
    if HAS_NATIVE_JOURNAL:
        reader = None
        try:
            log.debug(f"Attempting native journal read for {unit_name}...")
            if HAS_CYSYSTEMD:
                log.debug(f"Using cysystemd reader for {unit_name} logs.")
                reader = JournalReader()
                reader.open(JournalOpenMode.SYSTEM)
                unit_rule = Rule("_SYSTEMD_UNIT", unit_name)
                reader.add_filter(unit_rule)
                reader.seek_tail()
                count = 0
                temp_logs = []
                while count < num_lines and reader.previous():
                    record = reader.current_record
                    if record and isinstance(record.data, dict):
                        entry_data = record.data
                        ts = record.date if hasattr(record, 'date') else _parse_journal_entry_time(entry_data)
                        ts_str = ts.isoformat(timespec='milliseconds') if ts else "NoTimestamp"
                        msg = entry_data.get("MESSAGE", "NoMessage")
                        temp_logs.insert(0, f"{ts_str} - {msg}")
                        count += 1
                    elif record:
                        log.warning(f"Skipping non-dict cysystemd record data: {type(record.data)}")
                logs = temp_logs
            elif HAS_PYTHON_SYSTEMD:
                 log.debug(f"Using legacy python-systemd reader for {unit_name} logs.")
                 reader = JournalReader()
                 reader.add_match(_SYSTEMD_UNIT=unit_name)
                 reader.seek_tail()
                 count = 0
                 temp_logs = []
                 while count < num_lines and reader.previous():
                     entry = reader.get_data()
                     if not isinstance(entry, dict):
                         continue
                     ts = _parse_journal_entry_time(entry)
                     ts_str = ts.isoformat(timespec='milliseconds') if ts else "NoTimestamp"
                     msg = entry.get("MESSAGE", "NoMessage")
                     temp_logs.insert(0, f"{ts_str} - {msg}")
                     count += 1
                 logs = temp_logs
            log.debug(f"Fetched {len(logs)} lines for {unit_name} via native journal.")
            return logs
        except Exception as e:
            error_msg = f"Native journal access failed for {unit_name}: {e}"
            log.warning(error_msg, exc_info=True)
        finally:
            if reader and hasattr(reader, 'close'):
                try:
                    reader.close()
                except Exception:
                    log.debug("Exception while closing native journal reader", exc_info=True)

    log.debug(f"Using journalctl fallback for {unit_name} logs.")
    command = ["journalctl", "-u", unit_name, "-n", str(num_lines), "--no-pager", "--output=short-iso"]
    success, stdout, stderr = run_subprocess(command)
    if success:
        logs = stdout.strip().splitlines()
        log.debug(f"Fetched {len(logs)} lines for {unit_name} via journalctl fallback.")
    else:
        fallback_error = f"journalctl command failed for {unit_name}: {stderr.strip() or stdout.strip() or 'Unknown error'}"
        log.warning(fallback_error)
        final_error = f"{error_msg}. Fallback failed: {fallback_error}" if error_msg else fallback_error
        logs = [f"[Error fetching logs: {final_error}]"]
    return logs


# --- Core Analysis Logic (Modified Signature) ---
def analyze_health(
    units: List[UnitHealthInfo], # Accept the pre-fetched list
    dbus_manager: Optional[Any] = None
) -> HealthAnalysisResult:
    """
    Performs service health analysis on the provided list of units,
    identifying failed, flapping, and problematic socket/timer units.
    Attempts to fetch details via DBus (if manager provided) or fallback.

    Args:
        units: List of UnitHealthInfo objects (fetched by caller).
        dbus_manager: Optional pre-connected DBus systemd manager interface object.
    """
    log.info("Starting service health analysis...")
    result = HealthAnalysisResult()
    # Unit list is now provided externally
    # fetch_error is no longer generated here

    # Ensure DBus Manager is available if possible
    if dbus_manager is None and HAS_DBUS:
        log.debug("DBus manager not provided, attempting to connect...")
        dbus_manager = _get_systemd_manager_interface()

    dbus_bus = dbus_manager.bus if dbus_manager and hasattr(dbus_manager, 'bus') else None

    # Check if units list is empty
    if not units:
         log.warning("No systemd units provided for health analysis.")
         result.analysis_error = "No systemd units provided for analysis."
         return result

    result.all_units_count = len(units)
    log.info(f"Analyzing {result.all_units_count} provided units...")

    # Analyze Each Unit (Logic remains mostly the same, uses provided 'units' list)
    for unit in units:
        try:
            details: Optional[Dict[str, Any]] = None
            fetch_details_attempted = False
            needs_details = (
                unit.active_state == 'failed' or
                unit.name.endswith(('.service', '.socket', '.timer'))
            )

            if needs_details:
                 log.debug(f"Fetching details for unit: {unit.name}")
                 # Prioritize DBus if available and path known
                 if dbus_bus and unit.path:
                     details = _get_unit_properties_dbus(dbus_bus, unit.path)
                     if details is not None:
                          log.debug(f"DBus details fetched for {unit.name}. Keys: {list(details.keys())}")
                     else:
                          log.debug(f"DBus details fetch returned None for {unit.name}.")
                 # Fallback to systemctl show if DBus failed or wasn't applicable
                 if details is None:
                     log.debug(f"DBus details failed or not applicable for {unit.name}, using systemctl show fallback.")
                     details = _get_unit_properties_fallback(unit.name)
                     if details is not None:
                          log.debug(f"Fallback details fetched for {unit.name}. Keys: {list(details.keys())}")
                     else:
                          log.debug(f"Fallback details fetch returned None for {unit.name}.")

                 fetch_details_attempted = True
                 # Assign to unit.details AFTER fetching, ensure it's a dict
                 unit.details = details if isinstance(details, dict) else {}
                 # Log if MainPID was found (for debugging child process issue)
                 if unit.name.endswith(".service") and 'MainPID' in unit.details:
                      log.debug(f"Found MainPID {unit.details['MainPID']} for {unit.name} in details.")


            # --- Perform Checks ---
            if unit.active_state == 'failed':
                unit.is_failed = True
                # Fetch logs only for units identified as problematic
                unit.recent_logs = _get_unit_logs(unit.name)
                result.failed_units.append(unit)
                log.debug(f"Identified failed unit: {unit.name}")
                continue # Skip other checks if failed

            # Check for flapping (only for services)
            if unit.name.endswith('.service'):
                 # Ensure details were fetched if needed
                 if needs_details and not fetch_details_attempted:
                      # If details weren't fetched because DBus/fallback failed, log and skip
                      if details is None:
                           log.warning(f"Details required but could not be fetched for potential flapping check on {unit.name}")
                           continue
                      # This case shouldn't happen if needs_details is true, but as a safeguard:
                      log.warning(f"Logic error: Details needed but not fetched for flapping check on {unit.name}")
                      continue

                 # Check NRestarts from details (which is now guaranteed to be a dict if populated)
                 n_restarts_val = unit.details.get('NRestarts') # Could be int (dbus) or str (fallback)
                 n_restarts = 0
                 if n_restarts_val is not None:
                     try:
                         n_restarts = int(n_restarts_val)
                     except (ValueError, TypeError):
                          log.warning(f"Could not parse NRestarts value '{n_restarts_val}' for unit {unit.name}")

                 if n_restarts >= FLAPPING_RESTART_THRESHOLD: # Use >= for threshold
                     unit.is_flapping = True
                     unit.recent_logs = _get_unit_logs(unit.name)
                     result.flapping_units.append(unit)
                     log.debug(f"Identified potentially flapping unit: {unit.name} (Restarts: {n_restarts})")
                     continue # Skip other checks if flapping

            # Check sockets
            if unit.name.endswith('.socket'):
                 if needs_details and not fetch_details_attempted:
                      if details is None:
                           log.warning(f"Details required but could not be fetched for socket check on {unit.name}")
                           continue
                      log.warning(f"Logic error: Details needed but not fetched for socket check on {unit.name}")
                      continue

                 # Check 'Refused' property (handles bool from dbus or 'yes'/'no' from fallback)
                 refused_prop = unit.details.get('Refused')
                 is_refused = False
                 if isinstance(refused_prop, bool):
                     is_refused = refused_prop
                 elif isinstance(refused_prop, str):
                     is_refused = refused_prop.lower() == 'yes'

                 # Check if state is unexpected (neither active/listening nor inactive)
                 # Allow 'running' as some sockets might show this transiently?
                 problematic_state = unit.active_state not in ('active', 'inactive') or \
                                     (unit.active_state == 'active' and unit.sub_state not in ('listening', 'running'))

                 if is_refused or problematic_state:
                     unit.is_problematic_socket = True
                     if is_refused:
                          unit.error_message = "Socket is refusing connections (Refused=yes)."
                     elif problematic_state:
                          unit.error_message = f"Socket in potentially problematic state: {unit.active_state or '?'}/{unit.sub_state or '?'}"
                     else: # Should not happen based on logic, but as fallback
                          unit.error_message = "Socket identified as problematic (unknown reason)."

                     unit.recent_logs = _get_unit_logs(unit.name)
                     result.problematic_sockets.append(unit)
                     log.debug(f"Identified problematic socket ({unit.error_message}): {unit.name}")
                     continue # Skip other checks

            # Check timers
            if unit.name.endswith('.timer'):
                 if needs_details and not fetch_details_attempted:
                      if details is None:
                           log.warning(f"Details required but could not be fetched for timer check on {unit.name}")
                           continue
                      log.warning(f"Logic error: Details needed but not fetched for timer check on {unit.name}")
                      continue

                 # Check 'Result' property (success is the only good outcome)
                 last_result = unit.details.get('Result', 'success') # Default to success if missing
                 timer_failed = last_result != 'success'

                 # Check if state is unexpected
                 problematic_state = unit.active_state not in ('active', 'inactive') or \
                                     (unit.active_state == 'active' and unit.sub_state not in ('waiting', 'running'))

                 if timer_failed or problematic_state:
                     unit.is_problematic_timer = True
                     if timer_failed:
                          unit.error_message = f"Timer last run resulted in '{last_result}'."
                     elif problematic_state:
                          unit.error_message = f"Timer in potentially problematic state: {unit.active_state or '?'}/{unit.sub_state or '?'}"
                     else:
                          unit.error_message = "Timer identified as problematic (unknown reason)."

                     unit.recent_logs = _get_unit_logs(unit.name)
                     result.problematic_timers.append(unit)
                     log.debug(f"Identified problematic timer ({unit.error_message}): {unit.name}")
                     continue # Skip other checks

        except Exception as e:
            # Catch errors during analysis of a single unit
            log.error(f"Error analyzing unit {unit.name}: {e}", exc_info=True)
            # Add error message to the unit itself if possible
            if unit:
                 unit.error_message = f"Analysis error: {e}"
            # Optionally add to overall analysis error list? For now, log is sufficient.

    log.info(f"Health analysis finished. Found: {len(result.failed_units)} failed, "
             f"{len(result.flapping_units)} flapping, {len(result.problematic_sockets)} socket issues, "
             f"{len(result.problematic_timers)} timer issues.")
    return result
