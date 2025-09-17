# tests/test_unit_analyzer.py
# -*- coding: utf-8 -*-

import pytest
from unittest.mock import patch, MagicMock

# Module to test
from sysdiag_analyzer import unit_analyzer
from sysdiag_analyzer.datatypes import (
    SingleUnitReport,
    UnitResourceUsage,
    FailedUnitDependencyInfo,
)

# --- Fixtures ---


@pytest.fixture
def mock_dbus_manager():
    """Provides a mock DBus manager object."""
    mock_manager = MagicMock()
    mock_manager.bus = MagicMock()
    return mock_manager


@pytest.fixture
def mock_unit_properties():
    """Provides a sample dictionary of unit properties."""
    return {
        "Id": "test.service",
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "running",
        "Description": "Test Service",
        "MainPID": 1234,
        "Requires": "dep1.service",
        "Wants": "dep2.target",
        "After": "network.target dep1.service",
    }


# --- Test Cases ---


@patch("sysdiag_analyzer.unit_analyzer._get_unit_properties_fallback")
@patch("sysdiag_analyzer.unit_analyzer.get_unit_resource_usage")
@patch("sysdiag_analyzer.unit_analyzer._analyze_single_unit_dependencies")
@patch("sysdiag_analyzer.unit_analyzer._get_unit_logs")
def test_run_single_unit_analysis_success(
    mock_get_logs,
    mock_analyze_deps,
    mock_get_resources,
    mock_get_props,
    mock_dbus_manager,
    mock_unit_properties,
):
    """Test the successful analysis of a single unit."""
    # Setup mocks
    mock_get_props.return_value = mock_unit_properties
    mock_get_logs.return_value = ["log line 1", "log line 2"]
    mock_get_resources.return_value = [
        UnitResourceUsage(name="test.service", cpu_usage_nsec=1e9)
    ]
    mock_analyze_deps.return_value = FailedUnitDependencyInfo(unit_name="test.service")

    # Run analysis
    report = unit_analyzer.run_single_unit_analysis("test.service", mock_dbus_manager)

    # Assertions
    assert isinstance(report, SingleUnitReport)
    assert report.analysis_error is None

    # Unit Info
    assert report.unit_info is not None
    assert report.unit_info.name == "test.service"
    assert report.unit_info.active_state == "active"
    assert len(report.unit_info.recent_logs) == 2

    # Resource Usage
    assert report.resource_usage is not None
    assert report.resource_usage.cpu_usage_nsec == 1e9

    # Dependencies
    assert report.dependency_info is not None

    # Verify mocks were called
    mock_get_props.assert_called_once_with("test.service")
    mock_get_logs.assert_called_once_with("test.service", num_lines=50)
    mock_get_resources.assert_called_once()
    mock_analyze_deps.assert_called_once_with(
        "test.service", mock_unit_properties, mock_dbus_manager
    )


@patch("sysdiag_analyzer.unit_analyzer._get_unit_properties_fallback")
def test_run_single_unit_analysis_not_found(mock_get_props, mock_dbus_manager):
    """Test the case where the unit to be analyzed is not found."""
    mock_get_props.return_value = None

    report = unit_analyzer.run_single_unit_analysis(
        "non-existent.service", mock_dbus_manager
    )

    assert isinstance(report, SingleUnitReport)
    assert report.analysis_error is not None
    assert "not found" in report.analysis_error
    assert report.unit_info is None
    assert report.resource_usage is None
    mock_get_props.assert_called_once_with("non-existent.service")


@patch("sysdiag_analyzer.unit_analyzer._get_unit_properties_fallback")
@patch("sysdiag_analyzer.unit_analyzer.get_unit_resource_usage")
@patch("sysdiag_analyzer.unit_analyzer._get_unit_logs")
def test_run_single_unit_analysis_partial_failure(
    mock_get_logs,
    mock_get_resources,
    mock_get_props,
    mock_dbus_manager,
    mock_unit_properties,
):
    """Test resilience when a sub-analysis (e.g., resources) fails."""
    mock_get_props.return_value = mock_unit_properties
    mock_get_logs.return_value = ["log line 1"]
    mock_get_resources.side_effect = Exception("Cgroup read failed")

    # The dependency analysis should still run
    with patch(
        "sysdiag_analyzer.unit_analyzer._analyze_single_unit_dependencies"
    ) as mock_analyze_deps:
        mock_analyze_deps.return_value = FailedUnitDependencyInfo(
            unit_name="test.service"
        )
        report = unit_analyzer.run_single_unit_analysis(
            "test.service", mock_dbus_manager
        )

        # Assertions
        assert report.analysis_error is None  # Overall analysis should not fail
        assert report.unit_info is not None
        assert report.dependency_info is not None

        # Check that the resource analysis part captured its specific error
        assert report.resource_usage is not None
        assert report.resource_usage.error == "Analysis failed: Cgroup read failed"

        mock_analyze_deps.assert_called_once()
