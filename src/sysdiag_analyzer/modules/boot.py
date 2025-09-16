import os
import subprocess
import logging
import re
import datetime
import json # Needed for fallback
from typing import List, Optional, Tuple, Dict, Any
from concurrent.futures import ThreadPoolExecutor, Future
from ..datatypes import BootAnalysisResult, BootTimes, BootBlameItem, CriticalChainItem
# Import run_subprocess directly for use in _get_critical_chain_sync
from ..utils import run_subprocess

log = logging.getLogger(__name__)
# Create a specific logger for blame processing details if needed
log_blame_detail = logging.getLogger(__name__ + ".blame_detail")
# Set its level to DEBUG if you want to see the detailed entry logs
# log_blame_detail.setLevel(logging.DEBUG)



# --- Native Journal Binding Detection ---
HAS_CYSYSTEMD = False
HAS_PYTHON_SYSTEMD = False
JournalReader = None
JournalOpenMode = None
Rule = None
journal = None # Keep `journal` name for compatibility in `_get_unit_logs` if needed

try:
    # cysystemd reader uses JournalOpenMode.SYSTEM etc flags in open()
    from cysystemd.reader import JournalReader, JournalOpenMode, Rule # type: ignore
    HAS_CYSYSTEMD = True
    log.debug("Successfully imported cysystemd bindings (preferred).")
except ImportError:
    log.debug("cysystemd bindings not found.")
    try:
        # Fallback check for older python-systemd
        # python-systemd reader uses methods like this_boot() after Reader()
        from systemd import journal # type: ignore
        HAS_PYTHON_SYSTEMD = True
        # Map python-systemd Reader to expected name for simplicity later
        JournalReader = journal.Reader # type: ignore
        log.warning("Imported legacy python-systemd bindings.")
    except ImportError:
        log.warning("No native systemd journal bindings found (cysystemd or python-systemd). Journal analysis will use 'journalctl'.")
        # Define dummy classes if needed elsewhere, though direct use is minimized now
        class JournalReader:
            pass
        class JournalOpenMode:
            # Add dummy attributes if they might be accessed before check
            SYSTEM = None
            CURRENT_USER = None
            # Add others if needed
            pass
        class Rule:
            pass
        class journal:
            @staticmethod
            def Reader():
                raise NotImplementedError

# Flag indicating if *any* native binding is available
HAS_NATIVE_JOURNAL = HAS_CYSYSTEMD or HAS_PYTHON_SYSTEMD

# Patterns and Constants
TIME_VALUE_PATTERN = r"[\d.]+\s?[a-z]+"
BOOT_TIME_LINE_PATTERN = re.compile(
    r"Startup finished in\s+"
    r"(?:(?P<firmware>" + TIME_VALUE_PATTERN + r")\s+\(firmware\)\s*\+?\s*)?"
    r"(?:(?P<loader>" + TIME_VALUE_PATTERN + r")\s+\(loader\)\s*\+?\s*)?"
    r"(?:(?P<kernel>" + TIME_VALUE_PATTERN + r")\s+\(kernel\)\s*\+?\s*)?"
    r"(?:(?P<initrd>" + TIME_VALUE_PATTERN + r")\s+\(initrd\)\s*\+?\s*)?" # Corrected ')' here
    r"(?:(?P<userspace>" + TIME_VALUE_PATTERN + r")\s+\(userspace\)\s*\+?\s*)?"
    r"\s*=\s+(?P<total>" + TIME_VALUE_PATTERN + r")"
)
# Critical Chain: Revised Regex
# - Make indent_prefix greedy to capture all leading space/tree chars
# - Make unit name non-greedy but ensure it captures something meaningful
# - Keep time parts optional and anchored at the end
CRITICAL_CHAIN_LINE_PATTERN = re.compile(
    r"^(?P<indent_prefix>[\s└├│`-]*)?"  # Optional indent/tree chars (greedy - capture all)
    r"(?P<unit>.+?)"                     # Unit name: one or more chars, non-greedy
    r"(?:\s+(?P<time_at>@[\s\d.]+\w*))?"   # Optional time_at (@...)
    r"(?:\s+(?P<time_delta>\+[\d.]+\w*))?$" # Optional time_delta (+...) at the end
)

UNIT_STARTING_MSG_SUBSTRING = "Starting " # Substring match
UNIT_STARTED_MSG_SUBSTRING = "Started "   # Substring match
HEADER_KEYWORDS = ["the time", "bootup is", "failed to determine", "graphical.target reached", "character", "after the", "unit takes"] # Added more keywords
TREE_CHARS = "└├│`─-" # Characters used for tree drawing

# --- _get_boot_times_sync ---
def _get_boot_times_sync() -> BootTimes:
    # ... (Function remains unchanged) ...
    log.debug("Getting boot times (Firmware/Loader via CLI, others TODO/fallback)...")
    result = BootTimes()
    command = ["systemd-analyze"]
    env_vars = {'LANG': 'C', 'LC_ALL': 'C'}
    success = False
    stdout = ""
    stderr = ""
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, **env_vars}
        )
        success = process.returncode == 0
        stdout = process.stdout
        stderr = process.stderr
    except Exception as e:
        log.exception(f"Failed running '{' '.join(command)}': {e}")
        result.error = f"systemd-analyze command failed: {e}"
        return result

    if not success:
        result.error = f"systemd-analyze command failed: {stderr or stdout or 'Unknown error'}"
        return result

    found_match = False
    for line in stdout.splitlines():
        line = line.strip()
        match = BOOT_TIME_LINE_PATTERN.search(line)
        if match:
            data = match.groupdict()
            result.firmware = data.get("firmware")
            result.loader = data.get("loader")
            result.kernel = data.get("kernel")
            result.initrd = data.get("initrd")
            result.userspace = data.get("userspace")
            result.total = data.get("total")
            if result.total:
                log.debug(f"Parsed basic times from systemd-analyze: {result}")
                found_match = True
                break # Stop on first match

    if not found_match:
        log.warning("Could not parse overall boot times from 'systemd-analyze' output.")
        pass # Explicit pass for clarity

    log.debug("Native Journal parsing for Kernel/Userspace times not yet implemented.")

    if not result.total and not result.error:
        result.error = "Failed to determine boot times from output."

    return result

# --- _parse_journal_entry_time ---
def _parse_journal_entry_time(entry_data: Dict[str, Any]) -> Optional[datetime.datetime]:
    # ... (Function remains unchanged) ...
    """Parses __REALTIME_TIMESTAMP from dict (for python-systemd/journalctl)."""
    ts_usec_val = entry_data.get("__REALTIME_TIMESTAMP")
    if ts_usec_val is not None:
        try:
            ts_usec = int(ts_usec_val)
            return datetime.datetime.fromtimestamp(ts_usec / 1_000_000, tz=datetime.timezone.utc)
        except (ValueError, TypeError) as e:
            log.warning(f"Could not parse journal timestamp: {ts_usec_val!r}. Error: {e}")
    return None

# --- _get_boot_blame_journal ---
def _get_boot_blame_journal() -> Tuple[List[BootBlameItem], Optional[str]]:
    # ... (Function remains unchanged - uses record.date for cysystemd) ...
    """
    Calculates unit activation times by parsing the systemd journal.
    Uses native cysystemd (preferred) or python-systemd bindings if available,
    otherwise falls back to parsing 'journalctl' JSON output.
    Handles unit restarts correctly.
    """
    log.debug("Calculating boot blame via journal (Native Preferred)...")
    blame_list: List[BootBlameItem] = []
    error: Optional[str] = None
    unit_starts: Dict[str, datetime.datetime] = {}
    unit_times: Dict[str, float] = {}
    processed_count = 0
    native_attempted = False
    entries_read = 0 # Count entries read from source
    skipped_for_missing_fields = 0 # Counter for debugging

    try:
        journal_iterable = [] # Iterable for entries (either native records or dicts)
        source_type = "unknown" # Track where entries came from

        # --- Native Path ---
        if HAS_NATIVE_JOURNAL:
            native_attempted = True
            reader = None
            try:
                if HAS_CYSYSTEMD:
                    log.debug("Using cysystemd journal reader.")
                    source_type = "cysystemd"
                    reader = JournalReader()
                    reader.open(JournalOpenMode.SYSTEM)
                    reader.seek_head()
                    log.debug("Setting journal iterable for cysystemd...")
                    journal_iterable = reader # Directly iterate over the reader

                elif HAS_PYTHON_SYSTEMD:
                    log.debug("Using legacy python-systemd journal reader.")
                    source_type = "python-systemd"
                    reader = JournalReader()
                    reader.this_boot()
                    log.debug("Setting journal iterable for python-systemd...")
                    journal_iterable = reader # Directly iterate over the reader

            except Exception as e:
                 log.error(f"Error reading native journal ({source_type}): {e}. Falling back to journalctl.", exc_info=True)
                 error = f"Error reading native journal ({source_type}): {e}"
                 journal_iterable = [] # Ensure iterable is empty on error
            # No finally block needed here, process loop handles iteration

        # --- Fallback Path ---
        if not native_attempted or error:
            log.debug("Using fallback: parsing 'journalctl -o json' output.")
            source_type = "journalctl"
            command = [
                "journalctl", "-b", "0", "-o", "json",
                "--output-fields=__REALTIME_TIMESTAMP,_SYSTEMD_UNIT,MESSAGE"
            ]
            success, stdout, stderr = run_subprocess(command)
            if not success:
                error_msg = f"journalctl command failed: {stderr or stdout or 'Unknown journalctl error'}"
                log.error(error_msg)
                error = f"{error}. {error_msg}" if error else error_msg
                return [], error

            journal_iterable = stdout.splitlines()
            entries_read = len(journal_iterable)
            log.debug(f"Prepared {entries_read} lines from journalctl fallback.")
            error = None


        # --- Process Entries ---
        log.debug(f"Processing journal entries from source: {source_type}...")
        log_interval = 1000 # Log roughly every 1000 entries skipped

        for i, entry_source in enumerate(journal_iterable):
            entry_data: Optional[Dict] = None
            timestamp: Optional[datetime.datetime] = None
            unit: Optional[str] = None
            message: Optional[str] = ""

            try:
                if source_type == "cysystemd":
                    record = entry_source
                    if record and isinstance(record.data, dict):
                        entry_data = record.data
                        timestamp = record.date
                        unit = entry_data.get("_SYSTEMD_UNIT")
                        message = entry_data.get("MESSAGE", "")
                    else:
                        log.warning(f"Skipping non-dict cysystemd record data: {type(record.data)}")
                        continue

                elif source_type == "python-systemd":
                    entry = entry_source
                    entry_dict = entry
                    if hasattr(entry, 'data') and isinstance(entry.data, dict):
                         entry_dict = entry.data
                    if isinstance(entry_dict, dict):
                        entry_data = entry_dict
                        unit = entry_data.get("_SYSTEMD_UNIT")
                        message = entry_data.get("MESSAGE", "")
                        timestamp = _parse_journal_entry_time(entry_data)
                    else:
                        log.warning(f"Skipping non-dict python-systemd entry: {type(entry_dict)}")
                        continue

                elif source_type == "journalctl":
                    line = entry_source.strip()
                    if not line:
                        continue
                    try:
                        entry_data = json.loads(line)
                        unit = entry_data.get("_SYSTEMD_UNIT")
                        message = entry_data.get("MESSAGE", "")
                        timestamp = _parse_journal_entry_time(entry_data)
                    except json.JSONDecodeError as e:
                        log.warning(f"Failed to decode journal JSON line: {e} - Line: {line[:100]}...")
                        continue
                else:
                    log.error(f"Unknown source type '{source_type}' during processing.")
                    continue

                # --- Common Check for Essential Fields ---
                if not unit or not timestamp or not message:
                    skipped_for_missing_fields += 1
                    if log_blame_detail.isEnabledFor(logging.DEBUG):
                        if skipped_for_missing_fields % log_interval == 1 or not unit or not timestamp or not message:
                             reason = []
                             if not unit:
                                reason.append("missing _SYSTEMD_UNIT")
                             if not timestamp:
                                reason.append("missing/unparsed timestamp")
                             if not message:
                                reason.append("missing MESSAGE")
                             ts_val_log = entry_data.get('__REALTIME_TIMESTAMP') if entry_data else 'N/A'
                             if source_type == "cysystemd" and record:
                                 try:
                                    ts_val_log = record.get_realtime_usec()
                                 except:  # noqa: E722
                                    pass
                             message_snippet = message[:100] + '...' if message and len(message) > 100 else message
                             log_blame_detail.debug(
                                 f"Skipping entry {i}: Reason(s): {', '.join(reason)}. "
                                 f"Unit='{unit}', TS='{timestamp}', TS_Val='{ts_val_log}', Msg='{message_snippet}'"
                             )
                    continue

                processed_count += 1

                # Rest of the blame logic...
                if UNIT_STARTING_MSG_SUBSTRING in message:
                    unit_starts[unit] = timestamp
                elif UNIT_STARTED_MSG_SUBSTRING in message and unit in unit_starts:
                    start_time = unit_starts.pop(unit)
                    duration = (timestamp - start_time).total_seconds()

                    if duration > 0.001:
                        current_max_duration = unit_times.get(unit, 0.0)
                        if duration > current_max_duration:
                            unit_times[unit] = duration
                    elif duration <= 0:
                        log.debug(f"Ignored zero/negative duration for {unit}: {duration:.3f}s (Start: {start_time}, Stop: {timestamp})")

            except Exception as loop_error:
                log.error(f"Error processing journal entry {i} from {source_type}: {loop_error}", exc_info=True)
                continue

        if source_type in ["cysystemd", "python-systemd"]:
            entries_read = i + 1

        log.debug(f"Finished processing. Read ~{entries_read} entries from {source_type}.")
        log.debug(f"Processed {processed_count} journal entries with unit/timestamp/message.")
        log.debug(f"Skipped {skipped_for_missing_fields} entries due to missing fields during processing.")
        if unit_starts:
             log.debug(f"Units missing corresponding 'Started' message after processing: {list(unit_starts.keys())}")

        blame_list = [
            BootBlameItem(time=f"{duration:.3f}s", unit=unit)
            for unit, duration in unit_times.items()
        ]

        try:
            blame_list.sort(key=lambda item: float(item.time[:-1]), reverse=True)
        except ValueError as e:
            log.error(f"Error sorting blame list - invalid time format? {e}")

    except Exception as e:
        log.exception("Unexpected error during journal processing for blame.")
        error = f"Journal processing failed unexpectedly: {e}"

    if not blame_list and not error:
        if processed_count > 0:
             log.warning("Processed journal entries but calculated no blame items.")
        elif entries_read > 0 and skipped_for_missing_fields == entries_read :
             log.warning("All read journal entries were skipped due to missing unit, timestamp, or message.")
        else:
            log.warning("No processable journal entries found for blame calculation.")

    log.debug(f"Calculated {len(blame_list)} final blame items.")
    return blame_list, error


# --- _get_critical_chain_sync ---
def _get_critical_chain_sync() -> Tuple[List[CriticalChainItem], Optional[str]]:
    """
    Gets critical chain using systemd-analyze critical-chain (CLI) and
    parses output using revised regex and indent calculation.
    """
    log.debug("Getting critical chain via 'systemd-analyze critical-chain' (CLI)...")
    command = ["systemd-analyze", "critical-chain"]
    env_vars = {'LANG': 'C', 'LC_ALL': 'C'}
    process = None
    stdout = ""
    stderr = ""
    success = False
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, **env_vars}
        )
        success = process.returncode == 0
        stdout = process.stdout or ""
        stderr = process.stderr or ""
    except FileNotFoundError:
        log.error(f"Command not found: {command[0]}. Is systemd-analyze installed and in PATH?")
        return [], f"Command not found: {command[0]}"
    except Exception as e:
        log.exception(f"An unexpected error occurred running command '{' '.join(command)}': {e}")
        return [], f"Unexpected error running systemd-analyze: {e}"


    chain_list: List[CriticalChainItem] = []
    error: Optional[str] = None

    if not success:
        log.error(f"Failed to run '{' '.join(command)}': {stderr}")
        error_detail = stderr.strip() or stdout.strip() or "Unknown error"
        error = f"systemd-analyze critical-chain command failed: {error_detail}"
        return chain_list, error

    lines = stdout.splitlines()
    start_index = 0
    # Skip potential header lines more robustly
    while start_index < len(lines):
        line_strip = lines[start_index].strip()
        if not line_strip: # Skip blank lines
            start_index += 1
            continue
        line_lower = line_strip.lower()
        # Check for keywords indicating a header or non-unit line
        if any(keyword in line_lower for keyword in HEADER_KEYWORDS):
            log.debug(f"Skipping potential header/blank line: {lines[start_index]!r}")
            start_index += 1
        else:
            log.debug(f"Chain likely starts at line: {lines[start_index]!r}")
            break

    for line_num, line in enumerate(lines[start_index:]):
        line = line.rstrip() # Keep leading spaces
        log.debug(f"Processing critical chain line {line_num} (after skip): {line!r}")

        match = CRITICAL_CHAIN_LINE_PATTERN.match(line)
        if not match:
            # Add a check: if the line doesn't match but isn't empty, log it as potentially unparseable
            if line.strip():
                 log.warning(f"Line {line_num} did not match critical chain regex: {line!r}")
            continue

        data = match.groupdict()
        indent_prefix = data.get("indent_prefix", "")
        unit_name = data.get("unit", "").strip() # Strip spaces around unit name
        time_at = data.get("time_at")
        time_delta = data.get("time_delta")

        # Calculate indent based on the length of the prefix string
        indent = len(indent_prefix) if indent_prefix else 0

        # Basic validation: unit name should not be empty
        if not unit_name:
             log.debug(f"Skipping line {line_num} (empty unit name after parsing)")
             continue

        # If the unit name still contains tree characters, it means the regex
        # might have failed to separate prefix correctly. This can happen with
        # unusual unit names or formatting. Let's try to strip them.
        # Use the module-level constant TREE_CHARS
        original_unit_name = unit_name
        unit_name = unit_name.lstrip(TREE_CHARS).strip()
        if unit_name != original_unit_name:
             log.debug(f"Stripped leading tree chars from unit name: '{original_unit_name}' -> '{unit_name}'")

        # Re-check if unit name became empty after stripping
        if not unit_name:
             log.debug(f"Skipping line {line_num} (unit name became empty after stripping tree chars)")
             continue

        # Relax the validation: If the regex matched and we have a non-empty unit name,
        # assume it's a valid entry for now. Further filtering could happen later if needed.
        log.debug(f"Adding Valid Chain Item: Ind={indent}, Unit={unit_name!r}, TA={time_at}, TD={time_delta}")
        chain_list.append(CriticalChainItem(
            unit=unit_name,
            time_at=time_at.strip() if time_at else None,
            time_delta=time_delta.strip() if time_delta else None,
            indent=indent
        ))

    if not chain_list and not error:
         # If we skipped headers but still got no units, report parsing failure
         if start_index < len(lines): # Check if there were non-header lines
              log.warning("Could not parse any valid units from 'systemd-analyze critical-chain' output.")
              error = "Failed to parse critical chain data from output (structure not recognized)."
         else: # Only headers/blank lines were present
              log.warning("No critical chain data found in 'systemd-analyze critical-chain' output (only headers/blank lines).")
              error = "No critical chain data available in output (only headers/blank lines)."

    log.debug(f"Final Parsed {len(chain_list)} critical chain items.")
    return chain_list, error


# --- analyze_boot ---
def analyze_boot() -> BootAnalysisResult:
    log.info("Starting boot analysis (Native Journal Blame Priority)...")
    result = BootAnalysisResult()
    futures: Dict[str, Future] = {}
    with ThreadPoolExecutor(max_workers=3, thread_name_prefix="BootAnalysis") as executor:
        futures["times"] = executor.submit(_get_boot_times_sync)
        futures["blame"] = executor.submit(_get_boot_blame_journal)
        futures["chain"] = executor.submit(_get_critical_chain_sync)

    try:
        result.times = futures["times"].result()
    except Exception as e:
        log.exception("Error retrieving boot times result.")
        if result.times is None:
            result.times = BootTimes()
        result.times.error = f"Failed to get result: {e}"
    try:
        blame_list, blame_err = futures["blame"].result()
        result.blame = blame_list
        # Don't wrap the error here, let the caller handle it if needed
        result.blame_error = blame_err
    except Exception as e:
        log.exception("Error retrieving boot blame result.")
        result.blame_error = f"Failed to get result: {e}"
    try:
        chain_list, chain_err = futures["chain"].result()
        result.critical_chain = chain_list
        # Don't wrap the error here
        result.critical_chain_error = chain_err
    except Exception as e:
        log.exception("Error retrieving critical chain result.")
        result.critical_chain_error = f"Failed to get result: {e}"

    log.info("Boot analysis finished.")
    return result
