# tests/modules/test_exporter.py
# -*- coding: utf-8 -*-

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

# Conditional import for prometheus_client
try:
    from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily

    HAS_PROMETHEUS_FOR_TEST = True
except ImportError:
    HAS_PROMETHEUS_FOR_TEST = False
    # Define dummy classes if prometheus_client is not installed
    class GaugeMetricFamily:
        pass

    class CounterMetricFamily:
        pass


# Module to test and its dependencies
from sysdiag_analyzer import exporter as exporter_logic
from sysdiag_analyzer.datatypes import (
    SystemReport,
    MLAnalysisResult,
    AnomalyInfo,
    HealthAnalysisResult,
    UnitHealthInfo,
    FullDependencyAnalysisResult,
    ResourceAnalysisResult,
    ChildProcessGroupUsage,
    LogAnalysisResult,
    LogPatternInfo,
    UnitResourceUsage,
)

# --- Fixtures ---

pytestmark_exporter = pytest.mark.skipif(
    not HAS_PROMETHEUS_FOR_TEST, reason="prometheus-client not installed"
)


@pytest.fixture
def mock_config():
    """Provides a default configuration dictionary."""
    return {
        "models": {"directory": "/fake/models"},
        "history": {"directory": "/fake/history"},
    }


@pytest.fixture
def mock_full_system_report():
    """Provides a SystemReport object with data for all metric types."""
    return SystemReport(
        hostname="test-host",
        ml_analysis=MLAnalysisResult(
            anomalies_detected=[AnomalyInfo(unit_name="anomaly.service", score=0.25)]
        ),
        health_analysis=HealthAnalysisResult(
            failed_units=[UnitHealthInfo(name="failed.service")],
            flapping_units=[UnitHealthInfo(name="flapping.service")],
            problematic_sockets=[UnitHealthInfo(name="bad.socket")],
        ),
        full_dependency_analysis=FullDependencyAnalysisResult(
            detected_cycles=[["A.service", "B.service"], ["C.service", "D.service"]]
        ),
        resource_analysis=ResourceAnalysisResult(
            unit_usage=[
                UnitResourceUsage(name="app.service", cpu_usage_nsec=123450000000)
            ],
            top_cpu_units=[
                UnitResourceUsage(name="app.service", cpu_usage_nsec=123450000000)
            ],
            child_process_groups=[
                ChildProcessGroupUsage(
                    parent_unit="app.service",
                    command_name="worker.py",
                    process_count=3,
                    aggregated_memory_bytes=100 * 1024 * 1024,
                    aggregated_cpu_seconds_total=123.45,
                )
            ],
        ),
        log_analysis=LogAnalysisResult(
            detected_patterns=[
                LogPatternInfo(
                    pattern_type="Error", pattern_key="segfault", level="ERR", count=3
                )
            ]
        ),
    )


@pytest.fixture
def mock_empty_system_report():
    """Provides an empty SystemReport object."""
    return SystemReport(
        hostname="test-host-empty",
        ml_analysis=MLAnalysisResult(),
        health_analysis=HealthAnalysisResult(),
        full_dependency_analysis=FullDependencyAnalysisResult(),
        resource_analysis=ResourceAnalysisResult(),
        log_analysis=LogAnalysisResult(),
    )


# --- Test Cases ---


@pytestmark_exporter
def test_collector_initialization(mock_config):
    """Test successful initialization of the SysdiagCollector."""
    collector = exporter_logic.SysdiagCollector(config=mock_config, interval=60)
    assert collector.interval == 60
    assert collector.model_dir == Path("/fake/models")
    assert collector.cached_report is None


@pytestmark_exporter
@patch("sysdiag_analyzer.exporter.HAS_PROMETHEUS_LIBS", False)
def test_collector_initialization_no_libs(mock_config):
    """Test that collector initialization fails if prometheus-client is missing."""
    with pytest.raises(
        ImportError, match="prometheus-client library is not installed"
    ):
        exporter_logic.SysdiagCollector(config=mock_config, interval=60)


@pytestmark_exporter
def test_collector_collect_with_full_report(mock_config, mock_full_system_report):
    """Verify that all metric types are correctly yielded from a full report."""
    collector = exporter_logic.SysdiagCollector(config=mock_config, interval=60)
    # Manually set the cached report to bypass the background thread
    collector.cached_report = mock_full_system_report

    # Collect metrics and store them in a dictionary for easy lookup
    yielded_metrics = list(collector.collect())
    metrics_by_name = {m.name: m for m in yielded_metrics}

    # Assert that all expected metrics were yielded
    expected_metric_names = [
        "sysdiag_analyzer_unit_anomaly_score",
        "sysdiag_analyzer_unit_problem_status",
        "sysdiag_analyzer_dependency_cycles_detected",
        "sysdiag_analyzer_child_process_group_memory_bytes",
        "sysdiag_analyzer_child_process_group_cpu_seconds",
        "sysdiag_analyzer_log_patterns_detected",
    ]
    for name in expected_metric_names:
        assert name in metrics_by_name, f"Metric '{name}' was not yielded"

    # --- Verify ML Anomaly Score ---
    anomaly_metric = metrics_by_name["sysdiag_analyzer_unit_anomaly_score"]
    assert isinstance(anomaly_metric, GaugeMetricFamily)
    assert len(anomaly_metric.samples) == 1
    sample = anomaly_metric.samples[0]
    assert sample.labels == {"unit": "anomaly.service"}
    assert sample.value == 0.25

    # --- Verify Unit Problem Status ---
    health_metric = metrics_by_name["sysdiag_analyzer_unit_problem_status"]
    assert isinstance(health_metric, GaugeMetricFamily)
    assert len(health_metric.samples) == 3
    health_samples = {
        (s.labels["unit"], s.labels["problem_type"]): s.value
        for s in health_metric.samples
    }
    assert health_samples[("failed.service", "failed")] == 1.0
    assert health_samples[("flapping.service", "flapping")] == 1.0
    assert health_samples[("bad.socket", "problematic_socket")] == 1.0

    # --- Verify Dependency Cycles ---
    cycles_metric = metrics_by_name["sysdiag_analyzer_dependency_cycles_detected"]
    assert isinstance(cycles_metric, GaugeMetricFamily)
    assert len(cycles_metric.samples) == 1
    assert cycles_metric.samples[0].value == 2

    # --- Verify Child Process Memory ---
    child_mem_metric = metrics_by_name[
        "sysdiag_analyzer_child_process_group_memory_bytes"
    ]
    assert isinstance(child_mem_metric, GaugeMetricFamily)
    assert len(child_mem_metric.samples) == 1
    sample = child_mem_metric.samples[0]
    assert sample.labels == {"parent_unit": "app.service", "command_name": "worker.py"}
    assert sample.value == 100 * 1024 * 1024

    # --- Verify Child Process CPU ---
    child_cpu_metric = metrics_by_name["sysdiag_analyzer_child_process_group_cpu_seconds"]
    assert isinstance(child_cpu_metric, CounterMetricFamily)
    assert len(child_cpu_metric.samples) == 1
    sample = child_cpu_metric.samples[0]
    assert sample.labels == {"parent_unit": "app.service", "command_name": "worker.py"}
    assert sample.value == 123.45

    # --- Verify Log Patterns ---
    log_metric = metrics_by_name["sysdiag_analyzer_log_patterns_detected"]
    assert isinstance(log_metric, CounterMetricFamily)
    assert len(log_metric.samples) == 1
    sample = log_metric.samples[0]
    assert sample.labels == {"pattern_key": "segfault", "level": "ERR"}
    assert sample.value == 3


@pytestmark_exporter
def test_collector_collect_with_empty_report(mock_config, mock_empty_system_report):
    """Verify that only metrics with a default value are yielded from an empty report."""
    collector = exporter_logic.SysdiagCollector(config=mock_config, interval=60)
    collector.cached_report = mock_empty_system_report

    yielded_metrics = list(collector.collect())
    # Only DEP_CYCLES should be yielded, as it always reports a value (0 in this case).
    assert len(yielded_metrics) == 1
    metric = yielded_metrics[0]
    assert metric.name == "sysdiag_analyzer_dependency_cycles_detected"
    assert len(metric.samples) == 1
    assert metric.samples[0].value == 0


@pytestmark_exporter
def test_collector_collect_with_no_cached_report(mock_config):
    """Verify that only the default dependency cycle metric is yielded if analysis hasn't run yet."""
    collector = exporter_logic.SysdiagCollector(config=mock_config, interval=60)
    collector.cached_report = None

    yielded_metrics = list(collector.collect())
    # Only DEP_CYCLES should be yielded, as it always reports a value (0 in this case).
    assert len(yielded_metrics) == 1
    metric = yielded_metrics[0]
    assert metric.name == "sysdiag_analyzer_dependency_cycles_detected"
    assert len(metric.samples) == 1
    assert metric.samples[0].value == 0


@pytestmark_exporter
@patch("sysdiag_analyzer.exporter.health.analyze_health")
@patch("sysdiag_analyzer.exporter.resources.analyze_resources")
@patch("sysdiag_analyzer.exporter.logs.analyze_general_logs")
@patch("sysdiag_analyzer.exporter.dependencies.analyze_full_dependency_graph")
@patch("sysdiag_analyzer.exporter.ml_engine.load_models", return_value=({}, {}, {}))
@patch("sysdiag_analyzer.exporter._get_all_units_dbus")
def test_collect_data_for_metrics_integration(
    mock_get_units,
    mock_load_models,
    mock_analyze_deps,
    mock_analyze_logs,
    mock_analyze_resources,
    mock_analyze_health,
):
    """Test the integration of the background data collection function."""
    # Setup mocks to return some data
    mock_get_units.return_value = ([UnitHealthInfo(name="test.service")], None)
    mock_analyze_health.return_value = HealthAnalysisResult(
        failed_units=[UnitHealthInfo(name="failed.service")]
    )
    mock_analyze_resources.return_value = ResourceAnalysisResult()
    mock_analyze_logs.return_value = LogAnalysisResult()
    mock_analyze_deps.return_value = FullDependencyAnalysisResult()

    # Call the function
    report = exporter_logic._collect_data_for_metrics(
        dbus_manager=MagicMock(), model_dir=Path("/fake/models")
    )

    # Verify that the analysis functions were called
    mock_get_units.assert_called_once()
    mock_analyze_health.assert_called_once()
    mock_analyze_resources.assert_called_once()
    mock_analyze_logs.assert_called_once()
    mock_analyze_deps.assert_called_once()
    mock_load_models.assert_called_once()

    # Verify that the report was populated
    assert report is not None
    assert report.health_analysis is not None
    assert len(report.health_analysis.failed_units) == 1
    assert report.errors == []

