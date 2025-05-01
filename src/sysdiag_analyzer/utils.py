import subprocess
import logging
import json # Added for get_boot_id
from pathlib import Path # Added for get_boot_id fallback
from typing import List, Tuple, Optional # Added Optional

log = logging.getLogger(__name__)

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
            text=True, # Decode stdout/stderr as text
            check=False # Don't raise exception on non-zero exit code
        )
        if process.returncode == 0:
            log.debug(f"Command '{' '.join(command)}' succeeded.")
            return True, process.stdout, process.stderr
        else:
            log.warning(f"Command '{' '.join(command)}' failed with exit code {process.returncode}.")
            log.debug(f"Stderr: {process.stderr.strip()}")
            return False, process.stdout, process.stderr

    except FileNotFoundError:
        log.error(f"Command not found: {command[0]}. Is it installed and in PATH?")
        return False, "", f"Command not found: {command[0]}"
    except Exception as e:
        log.exception(f"An unexpected error occurred running command '{' '.join(command)}': {e}")
        return False, "", f"Unexpected error: {e}"

# --- Added for Phase 7 ---
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
            # FIX: Handle JSON Lines output
            boot_entry = None
            last_valid_entry = None
            for line in stdout.strip().splitlines():
                try:
                    entry = json.loads(line)
                    if isinstance(entry, dict) and "boot_id" in entry:
                        last_valid_entry = entry # Keep track of the last valid entry
                except json.JSONDecodeError as e:
                    log.warning(f"Failed to parse JSON line from journalctl --list-boots: {e}. Line: '{line[:100]}...'")
                    # Continue to next line if one line fails

            if last_valid_entry:
                boot_id = last_valid_entry.get("boot_id")
                if boot_id:
                    log.debug(f"Retrieved boot ID via journalctl: {boot_id}")
                    _cached_boot_id = boot_id
                    return boot_id
                else:
                    # This case should be unlikely if "boot_id" was checked before assigning last_valid_entry
                    log.warning("Last valid journalctl boot entry unexpectedly missing 'boot_id'.")
            else:
                log.warning("Could not find any valid boot entry with 'boot_id' in journalctl output.")

        else:
            # Log failure only if stdout was empty or command failed
            if not success:
                 log.warning(f"journalctl --list-boots command failed. Stderr: {stderr}")
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
                 log.warning(f"Using boot ID from /proc/sys/kernel/random/boot_id: {boot_id_proc}")
                 _cached_boot_id = boot_id_proc
                 return boot_id_proc
             else:
                  log.warning("/proc/sys/kernel/random/boot_id was empty.")
         else:
              log.warning("/proc/sys/kernel/random/boot_id not found.")
    except Exception as e:
         log.error(f"Could not read boot ID from /proc/sys/kernel/random/boot_id: {e}", exc_info=True)

    log.error("Could not determine boot ID from journalctl or /proc.")
    return None
# --- End Phase 7 Additions ---
