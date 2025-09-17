# src/sysdiag_analyzer/features.py
import os
import gzip
import json
import logging
from pathlib import Path
from typing import List, Dict, Any

from .utils import deduplicate_report_data_in_memory

# Use try-except for datatypes import for potential standalone use/testing
try:
    from .datatypes import SystemReport
except ImportError:
    # Define dummy if needed for type hinting during isolated tests
    SystemReport = Dict[str, Any]

log_feat = logging.getLogger(__name__)


def load_historical_data(
    history_dir: Path, num_reports: int = 10
) -> List[Dict[str, Any]]:
    """Loads the last N historical reports from the specified history directory."""
    reports = []
    if not history_dir.is_dir():
        log_feat.warning(f"History directory not found: {history_dir}")
        return reports

    try:
        # List files matching the pattern, sort by modification time (newest first)
        history_files = sorted(
            history_dir.glob("report-*.jsonl.gz"),
            key=os.path.getmtime,
            reverse=True,
        )

        files_to_load = history_files[:num_reports]
        log_feat.info(
            f"Found {len(history_files)} reports in {history_dir}, attempting to load latest {len(files_to_load)}."
        )

        for report_file in files_to_load:
            try:
                with gzip.open(report_file, "rt", encoding="utf-8") as f:
                    # Read the single line containing the JSON report
                    json_line = f.readline()
                    if json_line:
                        report_dict = json.loads(json_line)
                        # Basic validation: check if it looks like a report
                        if isinstance(report_dict, dict) and "hostname" in report_dict:
                            reports.append(report_dict)
                        else:
                            log_feat.warning(
                                f"Skipping file {report_file.name}: Invalid report structure found."
                            )
                    else:
                        log_feat.warning(f"Skipping empty file: {report_file.name}")
            except (json.JSONDecodeError, gzip.BadGzipFile) as e:
                log_feat.error(
                    f"Failed to read or parse report file {report_file.name}: {e}"
                )
            except FileNotFoundError:
                log_feat.error(
                    f"File not found while loading history (likely race condition): {report_file.name}"
                )
            except Exception as e:
                log_feat.error(
                    f"Unexpected error loading report {report_file.name}: {e}",
                    exc_info=True,
                )

    except Exception as e:
        log_feat.error(
            f"Error listing history files in {history_dir}: {e}", exc_info=True
        )

    log_feat.info(f"Successfully loaded {len(reports)} historical reports.")
    return reports


# --- Feature Extraction Logic ---

def extract_features_from_report(
    report: Dict[str, Any], include_devices: bool = False
) -> List[Dict[str, Any]]:
    """
    Extracts raw features for each relevant unit FROM A SINGLE report dictionary.
    Focuses on metrics useful for anomaly detection or prediction.
    """
    features = []
    report_ts = report.get("timestamp")
    boot_id_from_report = report.get("boot_id", "unknown_boot")
    hostname = report.get("hostname", "unknown_host")
    unique_boot_id = (
        f"{hostname}_{boot_id_from_report}"
        if hostname and boot_id_from_report
        else boot_id_from_report or hostname or "unknown_session"
    )

    # Resource Analysis
    resource_analysis = report.get("resource_analysis")
    if resource_analysis and isinstance(resource_analysis.get("unit_usage"), list):
        for unit_usage in resource_analysis["unit_usage"]:
            if not isinstance(unit_usage, dict):
                continue
            unit_name = unit_usage.get("name")
            if not unit_name:
                continue

            if not include_devices:
                # **FILTERING LOGIC**: Exclude low-value units for ML
                if (
                    unit_name.endswith((".device", ".slice", ".scope"))
                    or "blockdev@" in unit_name
                ):
                    log_feat.debug(f"Skipping feature extraction for ML: {unit_name}")
                    continue

            features.append(
                {
                    "report_timestamp": report_ts,
                    "boot_id": unique_boot_id,
                    "unit_name": unit_name,
                    "source": "resource_analysis",
                    "cpu_usage_nsec": unit_usage.get("cpu_usage_nsec"),
                    "mem_current_bytes": unit_usage.get("memory_current_bytes"),
                    "mem_peak_bytes": unit_usage.get("memory_peak_bytes"),
                    "io_read_bytes": unit_usage.get("io_read_bytes"),
                    "io_write_bytes": unit_usage.get("io_write_bytes"),
                    "tasks_current": unit_usage.get("tasks_current"),
                    "resource_error": unit_usage.get("error"),
                }
            )

    # Health Analysis
    health_analysis = report.get("health_analysis")
    if health_analysis:
        for unit_list_key in [
            "failed_units",
            "flapping_units",
            "problematic_sockets",
            "problematic_timers",
        ]:
            unit_list = health_analysis.get(unit_list_key)
            if isinstance(unit_list, list):
                for unit_health in unit_list:
                    if not isinstance(unit_health, dict):
                        continue
                    unit_name = unit_health.get("name")
                    if not unit_name:
                        continue
                    features.append(
                        {
                            "report_timestamp": report_ts,
                            "boot_id": unique_boot_id,
                            "unit_name": unit_name,
                            "source": "health_analysis",
                            "is_failed": unit_list_key == "failed_units",
                            "is_flapping": unit_list_key == "flapping_units",
                            "is_problematic_socket": unit_list_key
                            == "problematic_sockets",
                            "is_problematic_timer": unit_list_key
                            == "problematic_timers",
                            "n_restarts": unit_health.get("details", {}).get(
                                "NRestarts"
                            ),
                            "health_error": unit_health.get("error_message"),
                        }
                    )

    # Boot Analysis (Blame)
    boot_analysis = report.get("boot_analysis")
    if boot_analysis and isinstance(boot_analysis.get("blame"), list):
        for blame_item in boot_analysis["blame"]:
            if not isinstance(blame_item, dict):
                continue
            unit_name = blame_item.get("unit")
            time_str = blame_item.get("time")
            if not unit_name or not time_str:
                continue
            try:
                time_sec = float(time_str.rstrip("s"))
            except ValueError:
                time_sec = None
            features.append(
                {
                    "report_timestamp": report_ts,
                    "boot_id": unique_boot_id,
                    "unit_name": unit_name,
                    "source": "boot_analysis",
                    "boot_blame_sec": time_sec,
                }
            )

    return features


def extract_features(
    historical_reports: List[Dict[str, Any]], include_devices: bool = False
) -> List[Dict[str, Any]]:
    """
    Extracts features from a list of historical report dictionaries,
    applying in-memory deduplication to each report before extraction if
    device training is enabled.
    """
    all_features = []
    log_feat.info(f"Starting feature extraction for {len(historical_reports)} reports...")
    for report_dict in historical_reports:
        if isinstance(report_dict, dict):
            cleaned_report = report_dict
            if include_devices:
                # Apply in-memory deduplication ONLY when training with devices
                cleaned_report = deduplicate_report_data_in_memory(report_dict)

            features_from_one_report = extract_features_from_report(
                cleaned_report, include_devices=include_devices
            )
            all_features.extend(features_from_one_report)
        else:
            log_feat.warning(
                f"Skipping non-dictionary item in historical_reports list: {type(report_dict)}"
            )

    log_feat.info(
        f"Finished feature extraction. Total feature sets extracted: {len(all_features)}"
    )
    return all_features
