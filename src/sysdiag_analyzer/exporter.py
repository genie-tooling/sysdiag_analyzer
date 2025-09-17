# src/sysdiag_analyzer/exporter.py
# -*- coding: utf-8 -*-

import logging
import time
import threading
from typing import Optional, List, Dict, Any
from pathlib import Path

# Local imports
from .datatypes import SystemReport, UnitHealthInfo
from .modules import (
    health,
    resources,
    logs,
    dependencies,
)
from . import ml_engine
from .features import extract_features_from_report
from .modules.health import (
    _get_systemd_manager_interface,
    _get_all_units_dbus,
    _get_all_units_json,
)
from dataclasses import asdict

# Conditional import for prometheus_client
PROMETHEUS_IMPORT_ERROR: Optional[ImportError] = None
try:
    from prometheus_client import REGISTRY
    from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily

    HAS_PROMETHEUS_LIBS = True
except ImportError as e:
    HAS_PROMETHEUS_LIBS = False
    PROMETHEUS_IMPORT_ERROR = e
    # Define dummy classes for type hinting if library is missing
    class GaugeMetricFamily:
        pass

    class CounterMetricFamily:
        pass

    REGISTRY = None

log = logging.getLogger(__name__)

# --- Prometheus Metrics Definitions ---
METRICS_PREFIX = "sysdiag_analyzer_"


def _collect_data_for_metrics(
    dbus_manager: Optional[Any], model_dir: Path
) -> Optional[SystemReport]:
    """
    Runs a targeted analysis to gather data specifically for the defined metrics.
    This is a lighter-weight version of the main `run_full_analysis`.
    """
    log.info("Exporter background thread: Starting periodic data collection...")
    report = SystemReport()
    try:
        # 1. Get unit list (essential for almost all other checks)
        all_units: List[UnitHealthInfo] = []
        fetch_error: Optional[str] = None
        if dbus_manager:
            all_units, fetch_error = _get_all_units_dbus(dbus_manager)
        if fetch_error or not all_units:
            all_units, fetch_error = _get_all_units_json()
        if fetch_error:
            report.errors.append(f"Failed to refresh unit list: {fetch_error}")

        # 2. Run analyses that feed our metrics
        if all_units:
            report.health_analysis = health.analyze_health(
                units=all_units, dbus_manager=dbus_manager
            )
            report.resource_analysis = resources.analyze_resources(
                units=all_units, dbus_manager=dbus_manager
            )
            # Only run failed dependency check if there are failed units
            if report.health_analysis and report.health_analysis.failed_units:
                report.dependency_analysis = dependencies.analyze_dependencies(
                    report.health_analysis.failed_units, dbus_manager
                )

        # Run analyses that don't depend on the unit list
        report.log_analysis = logs.analyze_general_logs()
        report.full_dependency_analysis = dependencies.analyze_full_dependency_graph()

        # 3. ML Analysis (if enabled/available)
        if ml_engine and ml_engine.HAS_ML_LIBS:
            anomaly_models = ml_engine.load_models(
                ml_engine.ANOMALY_MODEL_TYPE, model_dir
            )
            scalers = ml_engine.load_models(ml_engine.SCALER_MODEL_TYPE, model_dir)
            if anomaly_models and scalers:
                report.ml_analysis = ml_engine.MLAnalysisResult(
                    models_loaded_count=len(anomaly_models)
                )
                current_features_list = extract_features_from_report(asdict(report))
                if current_features_list:
                    current_features_df = ml_engine.pd.DataFrame(current_features_list)
                    current_features_df["report_timestamp"] = ml_engine.pd.to_datetime(
                        current_features_df["report_timestamp"]
                    )
                    engineered_df = ml_engine.engineer_features(current_features_df)
                    if not engineered_df.empty:
                        report.ml_analysis.anomalies_detected = ml_engine.detect_anomalies(
                            engineered_df, anomaly_models, scalers
                        )
            else:
                report.ml_analysis = ml_engine.MLAnalysisResult(
                    error="No trained models found."
                )

        log.info("Exporter background thread: Data collection finished successfully.")
        return report

    except Exception as e:
        log.exception(
            "Exporter background thread: Unhandled exception during data collection."
        )
        report.errors.append(f"Data collection failed: {e}")
        return report


class SysdiagCollector:
    """Custom Prometheus collector for sysdiag-analyzer."""

    def __init__(self, config: Dict[str, Any], interval: int):
        if not HAS_PROMETHEUS_LIBS:
            raise ImportError("prometheus-client library is not installed.")
        self.config = config
        self.interval = interval
        self.cached_report: Optional[SystemReport] = None
        self.lock = threading.Lock()
        self.dbus_manager = _get_systemd_manager_interface()
        self.model_dir = Path(
            config.get("models", {}).get(
                "directory", "/var/lib/sysdiag-analyzer/models"
            )
        )

    def run_periodic_analysis(self):
        """The main loop for the background thread to periodically collect data."""
        log.info(f"Starting periodic analysis thread (interval: {self.interval}s).")
        while True:
            report = _collect_data_for_metrics(self.dbus_manager, self.model_dir)
            with self.lock:
                self.cached_report = report
            time.sleep(self.interval)

    def collect(self):
        """
        This method is called by the Prometheus client library on every scrape.
        It yields metrics based on the latest cached report.
        """
        log.debug("Prometheus scrape received, serving metrics from cache.")

        # --- Instantiate metrics INSIDE collect to avoid state leakage ---
        ml_anomaly_score = GaugeMetricFamily(
            f"{METRICS_PREFIX}unit_anomaly_score",
            "ML anomaly score for a systemd unit. Lower scores are more anomalous.",
            labels=["unit"],
        )
        unit_problem_status = GaugeMetricFamily(
            f"{METRICS_PREFIX}unit_problem_status",
            "A gauge that is 1 if a unit has a specific problem (e.g., failed, flapping).",
            labels=["unit", "problem_type"],
        )
        dep_cycles = GaugeMetricFamily(
            f"{METRICS_PREFIX}dependency_cycles_detected",
            "Total number of circular dependencies detected in the full dependency graph.",
        )
        child_group_mem = GaugeMetricFamily(
            f"{METRICS_PREFIX}child_process_group_memory_bytes",
            "Aggregated memory usage (RSS) of a group of child processes under a parent systemd unit.",
            labels=["parent_unit", "command_name"],
        )
        child_group_cpu = CounterMetricFamily(
            f"{METRICS_PREFIX}child_process_group_cpu_seconds",
            "Aggregated cumulative CPU time (user + system) of a group of child processes under a parent systemd unit.",
            labels=["parent_unit", "command_name"],
        )
        log_patterns = CounterMetricFamily(
            f"{METRICS_PREFIX}log_patterns_detected",
            "Total number of times a specific log pattern (e.g., segfault, oom-killer) has been detected.",
            labels=["pattern_key", "level"],
        )

        with self.lock:
            report = self.cached_report

        if not report:
            log.warning("Serving no metrics: analysis has not completed yet.")
            # Yield dependency cycles gauge with 0 so the metric is always present
            dep_cycles.add_metric([], 0)
            yield dep_cycles
            return

        # --- ML Metrics ---
        if report.ml_analysis and report.ml_analysis.anomalies_detected:
            for anomaly in report.ml_analysis.anomalies_detected:
                ml_anomaly_score.add_metric([anomaly.unit_name], anomaly.score)
            if ml_anomaly_score.samples:
                yield ml_anomaly_score

        # --- Health Metrics ---
        if report.health_analysis:
            health = report.health_analysis
            for unit in health.failed_units:
                unit_problem_status.add_metric([unit.name, "failed"], 1.0)
            for unit in health.flapping_units:
                unit_problem_status.add_metric([unit.name, "flapping"], 1.0)
            for unit in health.problematic_sockets:
                unit_problem_status.add_metric([unit.name, "problematic_socket"], 1.0)
            for unit in health.problematic_timers:
                unit_problem_status.add_metric([unit.name, "problematic_timer"], 1.0)
            if unit_problem_status.samples:
                yield unit_problem_status

        # --- Dependency Metrics ---
        # Always yield this metric, even if 0, for consistent dashboards
        cycle_count = 0
        if report.full_dependency_analysis:
            cycle_count = len(report.full_dependency_analysis.detected_cycles)
        dep_cycles.add_metric([], cycle_count)
        yield dep_cycles

        # --- Resource Metrics (Child Processes) ---
        if report.resource_analysis and report.resource_analysis.child_process_groups:
            for group in report.resource_analysis.child_process_groups:
                labels = [group.parent_unit, group.command_name]
                if group.aggregated_memory_bytes is not None:
                    child_group_mem.add_metric(labels, group.aggregated_memory_bytes)
                if group.aggregated_cpu_seconds is not None:
                    child_group_cpu.add_metric(labels, group.aggregated_cpu_seconds)
            if child_group_mem.samples:
                yield child_group_mem
            if child_group_cpu.samples:
                yield child_group_cpu

        # --- Log Metrics ---
        if report.log_analysis and report.log_analysis.detected_patterns:
            for pattern in report.log_analysis.detected_patterns:
                log_patterns.add_metric(
                    [pattern.pattern_key, pattern.level or "unknown"], pattern.count
                )
            if log_patterns.samples:
                yield log_patterns