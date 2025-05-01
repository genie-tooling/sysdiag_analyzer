import logging
import re
import json
import datetime
import collections
from typing import List, Optional, Tuple, Dict, Any

# Use relative import for journal helpers from boot module
try:
    from .boot import (
        _parse_journal_entry_time,
        HAS_NATIVE_JOURNAL,
        HAS_CYSYSTEMD,
        HAS_PYTHON_SYSTEMD,
        JournalReader,
        JournalOpenMode,
        Rule, # Rule might still be used for other filters later
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

# Local imports
from ..datatypes import LogAnalysisResult, LogPatternInfo
from ..utils import run_subprocess

log = logging.getLogger(__name__)

# --- Constants ---
# Map journal priority levels (syslog standard)
LOG_LEVEL_MAP: Dict[int, str] = {
    0: "EMERG", 1: "ALERT", 2: "CRIT", 3: "ERR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG",
}
DEFAULT_ANALYSIS_LEVEL: int = 4 # Analyze WARNING (4) and higher by default
MAX_EXAMPLE_MESSAGES: int = 3
MAX_ENTRIES_TO_ANALYZE: int = 50000 # Safety limit to avoid excessive memory/CPU use

# --- Patterns ---
# OOM Killer Pattern (adjust based on common kernel messages)
OOM_PATTERN = re.compile(r"(Out of memory:|oom-killer:|memory cgroup out of memory)", re.IGNORECASE) # Added cgroup OOM

# Common Error Patterns (Key -> Regex)
# Focus on common indicators, avoid overly broad patterns initially
COMMON_ERROR_PATTERNS: Dict[str, re.Pattern] = {
    "segfault": re.compile(r"segfault.*ip\s+[0-9a-f]+.*sp\s+[0-9a-f]+.*error\s+\d+", re.IGNORECASE),
    "kernel-panic": re.compile(r"Kernel panic - not syncing:", re.IGNORECASE),
    "call-trace": re.compile(r"Call Trace:", re.IGNORECASE),
    "BUG:": re.compile(r"\bBUG:", re.IGNORECASE), # Kernel BUG messages
    "exception-trace": re.compile(r"exception trace:", re.IGNORECASE),
    "hardware-error": re.compile(r"\b(Hardware Error|MCA:)", re.IGNORECASE),
    # Add more specific application error patterns if needed, e.g.:
    # "nginx-emerg": re.compile(r"nginx.*\[emerg\]"),
}

# Common Warning Patterns (Key -> Regex)
COMMON_WARNING_PATTERNS: Dict[str, re.Pattern] = {
    "i/o-error": re.compile(r"\b(I/O error|Input/output error)\b", re.IGNORECASE),
    "filesystem-readonly": re.compile(r"Remounting filesystem read-only", re.IGNORECASE),
    "buffer-io-error": re.compile(r"Buffer I/O error", re.IGNORECASE),
    "task-blocked": re.compile(r"task .* blocked for more than \d+ seconds", re.IGNORECASE),
    # Add more specific application warning patterns if needed
}

# --- Helper Functions ---

def _format_log_entry(entry_data: Dict[str, Any], timestamp: Optional[datetime.datetime]) -> str:
    """Formats a log entry dictionary into a readable string."""
    ts_str = timestamp.isoformat(timespec='milliseconds') if timestamp else "NoTimestamp"
    prio_val = entry_data.get("PRIORITY")
    level_str = LOG_LEVEL_MAP.get(int(prio_val), "UNK") if prio_val is not None else "UNK"
    unit = entry_data.get("_SYSTEMD_UNIT", "system")
    pid = entry_data.get("_PID", "-")
    msg = entry_data.get("MESSAGE", "NoMessage")
    # Basic format, can be customized
    return f"{ts_str} [{level_str}] {unit}({pid}): {msg}"

def _update_pattern_counts(
    pattern_counts: Dict[str, LogPatternInfo],
    pattern_type: str,
    pattern_key: str,
    level_str: Optional[str],
    entry_data: Dict[str, Any],
    timestamp: Optional[datetime.datetime]
):
    """Helper to update counts and example messages for a matched pattern."""
    if pattern_key not in pattern_counts:
        pattern_counts[pattern_key] = LogPatternInfo(
            pattern_type=pattern_type,
            pattern_key=pattern_key,
            count=0,
            level=level_str,
            example_messages=[]
        )
    pattern_info = pattern_counts[pattern_key]
    pattern_info.count += 1
    if len(pattern_info.example_messages) < MAX_EXAMPLE_MESSAGES:
        pattern_info.example_messages.append(_format_log_entry(entry_data, timestamp))
    # Update level if a higher priority message matches the same key later?
    # For now, first level seen is kept. Could compare priorities if needed.
    if pattern_info.level is None and level_str:
         pattern_info.level = level_str


# --- Core Analysis Function ---

def analyze_general_logs(
    boot_offset: int = 0,
    min_priority: int = DEFAULT_ANALYSIS_LEVEL
) -> LogAnalysisResult:
    """
    Analyzes system logs from the specified boot for OOM events and common
    error/warning patterns. Prefers native journal reading.

    Args:
        boot_offset: 0 for current boot, -1 for previous, etc.
        min_priority: Minimum syslog priority level to analyze (0=emerg to 7=debug).

    Returns:
        LogAnalysisResult containing findings.
    """
    log.info(f"Starting general log analysis for boot {boot_offset} (min priority: {min_priority})...")
    result = LogAnalysisResult()
    # Use regular dict now, defaultdict lambda was complex
    pattern_counts: Dict[str, LogPatternInfo] = {}
    total_entries = 0
    native_attempted = False
    native_success = False
    json_decode_errors_occurred = False # Flag for fallback JSON errors

    # --- Native Path (cysystemd preferred) ---
    if HAS_NATIVE_JOURNAL:
        native_attempted = True
        reader = None
        try:
            log.debug("Attempting log analysis via native journal reader...")
            if HAS_CYSYSTEMD:
                result.log_source = "cysystemd"
                log.debug("Using cysystemd reader.")
                reader = JournalReader()
                reader.open(JournalOpenMode.SYSTEM) # Open system journal
                # TODO: Filter by boot ID if possible using cysystemd features
                # Example (needs testing): reader.seek_monotonic_usec(boot_id, some_timestamp)
                reader.seek_head() # Start from beginning of journal for the boot

                log.debug(f"Iterating through cysystemd entries (limit {MAX_ENTRIES_TO_ANALYZE})...")
                for record in reader:
                    if total_entries >= MAX_ENTRIES_TO_ANALYZE:
                        log.warning(f"Reached analysis limit of {MAX_ENTRIES_TO_ANALYZE} entries.")
                        result.analysis_error = (result.analysis_error or "") + f"; Reached entry limit ({MAX_ENTRIES_TO_ANALYZE})"
                        break
                    total_entries += 1 # Count every entry read before filtering

                    if not record or not isinstance(record.data, dict):
                        continue

                    entry_data = record.data
                    timestamp = record.date # Use accurate timestamp from record
                    message = entry_data.get("MESSAGE", "")
                    prio_val = entry_data.get("PRIORITY")

                    # --- Priority Filtering ---
                    if prio_val is not None:
                        try:
                            priority = int(prio_val)
                            # Lower number = higher priority. Skip if less severe than min_priority.
                            if priority > min_priority:
                                continue # Skip this entry
                        except (ValueError, TypeError):
                            log.warning(f"Could not parse priority '{prio_val}' for entry, skipping priority check.")
                            continue # Skip if priority cannot be determined
                    else:
                        log.debug("Skipping entry without PRIORITY field during native read.")
                        continue # Skip if no priority field
                    # --- End Priority Filtering ---

                    level_str = LOG_LEVEL_MAP.get(priority) if prio_val is not None else None

                    if not message: continue # Skip if no message content

                    # --- Pattern Matching ---
                    # Check OOM
                    if OOM_PATTERN.search(message):
                        _update_pattern_counts(pattern_counts, "OOM", "oom-killer", level_str, entry_data, timestamp)
                        continue # OOM is specific, don't check other patterns

                    # Check Errors
                    error_matched = False
                    for key, pattern in COMMON_ERROR_PATTERNS.items():
                        if pattern.search(message):
                            _update_pattern_counts(pattern_counts, "Error", key, level_str, entry_data, timestamp)
                            error_matched = True
                            break # Count first matching error pattern per message
                    if error_matched: continue

                    # Check Warnings
                    for key, pattern in COMMON_WARNING_PATTERNS.items():
                        if pattern.search(message):
                            _update_pattern_counts(pattern_counts, "Warning", key, level_str, entry_data, timestamp)
                            break # Count first matching warning pattern per message
                    # --- End Pattern Matching ---

                native_success = True # Reached end of loop or limit without exception
                log.debug(f"Native analysis processed {total_entries} entries (filtered by priority >= {min_priority}).")

            # elif HAS_PYTHON_SYSTEMD: # TODO: Implement if needed, similar logic
            #     result.log_source = "python-systemd"
            #     log.warning("Log analysis with python-systemd not fully implemented, may be incomplete.")
            #     # ... implementation ...
            #     native_success = True

        except Exception as e:
            error_msg = f"Native journal access failed during log analysis: {e}"
            log.warning(error_msg, exc_info=True) # Keep logging traceback here
            result.analysis_error = error_msg
            native_success = False # Ensure fallback is triggered
        finally:
            if reader and hasattr(reader, 'close'):
                try:
                    reader.close()
                except Exception: pass

    # --- Fallback Path (journalctl) ---
    if not native_success:
        log.info("Using journalctl fallback for log analysis.")
        result.log_source = "journalctl"
        # Reset counts if native path was attempted but failed partially
        if native_attempted:
             pattern_counts.clear()
             total_entries = 0 # Reset count as fallback reads everything again
             result.analysis_error = result.analysis_error or "Native read failed, using fallback."

        # Construct command (journalctl handles priority filtering via -p)
        priority_range = f"{min_priority}..0" # journalctl uses .. syntax
        command = [
            "journalctl", f"-b{boot_offset}", f"-p{priority_range}",
            "-o", "json", "--no-pager",
            # Request specific fields needed for parsing and formatting
            "--output-fields=__REALTIME_TIMESTAMP,PRIORITY,MESSAGE,_SYSTEMD_UNIT,_PID"
        ]
        log.debug(f"Executing fallback command: {' '.join(command)}")
        success, stdout, stderr = run_subprocess(command)

        if not success:
            error_msg = f"journalctl command failed: {stderr or stdout or 'Unknown error'}"
            log.error(error_msg)
            result.analysis_error = f"{result.analysis_error}; {error_msg}" if result.analysis_error else error_msg
            # Return early if command failed, no point parsing empty/error output
            result.detected_patterns = list(pattern_counts.values()) # Ensure list is empty
            return result

        log.debug(f"Parsing journalctl JSON output...")
        try:
            lines = stdout.splitlines()
            log.debug(f"Read {len(lines)} lines from journalctl.")
            for line in lines:
                # Fallback doesn't need MAX_ENTRIES check here, journalctl already limited output size implicitly
                if not line.strip(): continue

                try:
                    entry_data = json.loads(line)
                except json.JSONDecodeError as json_e:
                    log.warning(f"Skipping invalid JSON line: {json_e} - Line: {line[:100]}...")
                    json_decode_errors_occurred = True # Set flag
                    continue

                total_entries += 1 # Count entries processed by fallback
                timestamp = _parse_journal_entry_time(entry_data)
                message = entry_data.get("MESSAGE", "")
                prio_val = entry_data.get("PRIORITY")
                level_str = LOG_LEVEL_MAP.get(int(prio_val)) if prio_val is not None else None

                if not message: continue

                # --- Pattern Matching (same logic as native) ---
                # Check OOM
                if OOM_PATTERN.search(message):
                    _update_pattern_counts(pattern_counts, "OOM", "oom-killer", level_str, entry_data, timestamp)
                    continue

                # Check Errors
                error_matched = False
                for key, pattern in COMMON_ERROR_PATTERNS.items():
                    if pattern.search(message):
                        _update_pattern_counts(pattern_counts, "Error", key, level_str, entry_data, timestamp)
                        error_matched = True
                        break
                if error_matched: continue

                # Check Warnings
                for key, pattern in COMMON_WARNING_PATTERNS.items():
                    if pattern.search(message):
                        _update_pattern_counts(pattern_counts, "Warning", key, level_str, entry_data, timestamp)
                        break
                # --- End Pattern Matching ---

            log.debug(f"Fallback analysis processed {total_entries} entries.")

        except Exception as e:
            error_msg = f"Error processing journalctl output: {e}"
            log.exception(error_msg)
            result.analysis_error = f"{result.analysis_error}; {error_msg}" if result.analysis_error else error_msg

        # If JSON errors occurred during the loop, add a note to the overall error
        if json_decode_errors_occurred:
             json_err_msg = "Errors occurred while parsing journalctl JSON output (check logs for details)."
             result.analysis_error = f"{result.analysis_error}; {json_err_msg}" if result.analysis_error else json_err_msg


    # --- Finalize ---
    result.total_entries_analyzed = total_entries
    result.detected_patterns = sorted(
        list(pattern_counts.values()),
        key=lambda p: p.count, reverse=True
    )

    log.info(f"Log analysis finished. Analyzed {result.total_entries_analyzed} entries via {result.log_source}. Found {len(result.detected_patterns)} distinct patterns.")
    return result
