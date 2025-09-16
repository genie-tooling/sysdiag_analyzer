# tests/test_output.py
# -*- coding: utf-8 -*-

import pytest
import datetime
from unittest.mock import patch
from rich.console import Console

# Module to test
from sysdiag_analyzer import output
from sysdiag_analyzer.datatypes import (
    SystemReport,
    FullDependencyAnalysisResult,
    BootAnalysisResult,
    HealthAnalysisResult,
    ResourceAnalysisResult,
    LogAnalysisResult,
    DependencyAnalysisResult,
    MLAnalysisResult,
    LLMAnalysisResult,
    EBPFAnalysisResult,
    EBPFExecEvent,
    EBPFExitEvent,
    ChildProcessGroupUsage
)

# --- Fixtures ---

@pytest.fixture
def mock_console():
    """Provides a mocked Rich Console object."""
    return Console(record=True, width=120, force_terminal=True)

# --- Tests for format_full_dependency_report ---
# (These tests remain unchanged)
def test_format_full_dep_report_with_cycles(mock_console):
    result = FullDependencyAnalysisResult(
        detected_cycles=[['A.service', 'B.service'], ['C.service', 'D.service', 'E.service']]
    )
    output.format_full_dependency_report(result, mock_console)
    captured_output = mock_console.export_text()
    assert "Detected 2 Dependency Cycles" in captured_output
    assert "A.service -> B.service -> A.service" in captured_output

def test_format_full_dep_report_no_cycles(mock_console):
    result = FullDependencyAnalysisResult(detected_cycles=[])
    output.format_full_dependency_report(result, mock_console)
    captured_output = mock_console.export_text()
    assert "No dependency cycles detected" in captured_output

def test_format_full_dep_report_analysis_error(mock_console):
    result = FullDependencyAnalysisResult(analysis_error="Something went wrong")
    output.format_full_dependency_report(result, mock_console)
    captured_output = mock_console.export_text()
    assert "Analysis Error: Something went wrong" in captured_output

def test_format_full_dep_report_sub_errors(mock_console):
    result = FullDependencyAnalysisResult(
        analysis_error="Top-level failure",
        dependency_fetch_error="Could not run systemctl",
        graph_build_error="Networkx failed"
    )
    output.format_full_dependency_report(result, mock_console)
    captured_output = mock_console.export_text()
    assert "Fetch Error: Could not run systemctl" in captured_output
    assert "Graph Build Error: Networkx failed" in captured_output

def test_format_full_dep_report_none_input(mock_console):
    output.format_full_dependency_report(None, mock_console)
    captured_output = mock_console.export_text()
    assert captured_output.strip() == ""

@patch('sysdiag_analyzer.output.MAX_CYCLES_TO_SHOW', 2)
def test_format_full_dep_report_cycle_limit(mock_console):
    result = FullDependencyAnalysisResult(
        detected_cycles=[['A', 'B'], ['C', 'D'], ['E', 'F']]
    )
    output.format_full_dependency_report(result, mock_console)
    captured_output = mock_console.export_text()
    assert "Detected 3 Dependency Cycles" in captured_output
    assert "A -> B -> A" in captured_output
    assert "... (1 more cycles omitted) ..." in captured_output

# --- Tests for format_llm_report ---

def test_format_llm_report_success(mock_console):
    result = LLMAnalysisResult(
        synthesis="## LLM Synthesis\n\nThis is the analysis.",
        provider_used="ollama", model_used="test-model"
    )
    output.format_llm_report(result, mock_console)
    captured_output = mock_console.export_text()
    assert "LLM Synthesis & Recommendations" in captured_output
    assert "This is the analysis." in captured_output

def test_format_llm_report_error(mock_console):
    result = LLMAnalysisResult(error="LLM failed to load model.")
    output.format_llm_report(result, mock_console)
    captured_output = mock_console.export_text()
    assert "LLM Analysis Error: LLM failed to load model." in captured_output

def test_format_llm_report_none_input(mock_console):
    output.format_llm_report(None, mock_console)
    captured_output = mock_console.export_text()
    assert captured_output.strip() == ""

# --- Tests for format_ebpf_report ---

def test_format_ebpf_report_with_events(mock_console):
    """Test formatting eBPF results with exec and exit events."""
    ts1_ns = int(datetime.datetime(2024, 5, 10, 12, 0, 1, 123456).timestamp() * 1e9)
    ts2_ns = int(datetime.datetime(2024, 5, 10, 12, 0, 2, 654321).timestamp() * 1e9)
    ts3_ns = int(datetime.datetime(2024, 5, 10, 12, 0, 3, 987654).timestamp() * 1e9)

    result = EBPFAnalysisResult(
        exec_events=[
            EBPFExecEvent(timestamp_ns=ts1_ns, pid=1001, ppid=1, comm="bash", cgroup_id=12345, filename="/bin/bash", argv=["bash", "-c", "sleep 1"]),
            EBPFExecEvent(timestamp_ns=ts2_ns, pid=1002, ppid=1001, comm="sleep", cgroup_id=12345, filename="/bin/sleep", argv=["sleep", "1"]),
        ],
        exit_events=[
            EBPFExitEvent(timestamp_ns=ts3_ns, pid=1002, ppid=1001, comm="sleep", cgroup_id=12345, exit_code=0),
            EBPFExitEvent(timestamp_ns=ts3_ns + 1000000, pid=1001, ppid=1, comm="bash", cgroup_id=12345, exit_code=1),
        ]
    )
    output.format_ebpf_report(result, mock_console)
    captured_output = mock_console.export_text()
    
    assert "Events Captured: Execs=2, Exits=2" in captured_output
    lines = captured_output.split('\n')
    
    sleep_exit_line_found = False
    for line in lines:
        if "1002" in line and "1001" in line and "sleep" in line and " 0 " in line:
            sleep_exit_line_found = True
            break
    assert sleep_exit_line_found, "Did not find the rendered table row for the 'sleep' exit event"

    bash_exit_line_found = False
    for line in lines:
        # CORRECTED: Removed the check for "red" as it's not present in plain text export.
        # The test still correctly validates that the PID, PPID, command, and non-zero exit code are present.
        if "1001" in line and " 1 " in line and "bash" in line:
            bash_exit_line_found = True
            break
    assert bash_exit_line_found, "Did not find the rendered table row for the 'bash' exit event"

def test_format_ebpf_report_no_events(mock_console):
    result = EBPFAnalysisResult(exec_events=[], exit_events=[])
    output.format_ebpf_report(result, mock_console)
    captured_output = mock_console.export_text()
    assert "No eBPF process events captured" in captured_output

def test_format_ebpf_report_with_error(mock_console):
    result = EBPFAnalysisResult(error="BPF program load failed.")
    output.format_ebpf_report(result, mock_console)
    captured_output = mock_console.export_text()
    assert "eBPF Analysis Error: BPF program load failed." in captured_output

# --- Tests for format_resource_report ---

def test_format_resource_report_with_child_procs(mock_console):
    """Test resource formatting including the child process group table."""
    result = ResourceAnalysisResult(
        child_process_groups=[
            ChildProcessGroupUsage(command_name="python3", parent_unit="my_app.service", process_count=5, pids=[101, 102, 103], aggregated_cpu_seconds=95.5, aggregated_memory_bytes=200*1024*1024),
            ChildProcessGroupUsage(command_name="nginx", parent_unit="nginx.service", process_count=2, pids=[201, 202], aggregated_cpu_seconds=5.1, aggregated_memory_bytes=50*1024*1024),
        ]
    )
    output.format_resource_report(result, mock_console)
    captured_output = mock_console.export_text()

    assert "Resource Analysis" in captured_output
    assert "Child Process Group Usage" in captured_output
    
    # CORRECTED: Check for wrapped header text by asserting its parts exist.
    # This is more robust than checking for the full contiguous string.
    assert "Aggr. CPU" in captured_output
    assert "Time" in captured_output
    
    assert "Aggr. Memory" in captured_output
    assert "python3" in captured_output
    assert "1.6m" in captured_output # 95.5 seconds formatted as minutes
    assert "200.0 MiB" in captured_output

# --- Tests for format_rich_report integration ---
# (These tests remain the same)
@patch('sysdiag_analyzer.output.format_boot_report')
@patch('sysdiag_analyzer.output.format_health_report')
@patch('sysdiag_analyzer.output.format_resource_report')
@patch('sysdiag_analyzer.output.format_log_report')
@patch('sysdiag_analyzer.output.format_dependency_report')
@patch('sysdiag_analyzer.output.format_full_dependency_report')
@patch('sysdiag_analyzer.output.format_ml_report')
@patch('sysdiag_analyzer.output.format_llm_report')
@patch('sysdiag_analyzer.output.format_ebpf_report')
def test_format_rich_report_calls_all_formatters(
    mock_format_ebpf, mock_format_llm, mock_format_ml, mock_format_full_dep, mock_format_dep,
    mock_format_log, mock_format_resource, mock_format_health, mock_format_boot,
    mock_console
):
    report = SystemReport(
        boot_analysis=BootAnalysisResult(),
        health_analysis=HealthAnalysisResult(),
        resource_analysis=ResourceAnalysisResult(),
        log_analysis=LogAnalysisResult(),
        dependency_analysis=DependencyAnalysisResult(),
        full_dependency_analysis=FullDependencyAnalysisResult(),
        ml_analysis=MLAnalysisResult(),
        llm_analysis=LLMAnalysisResult(),
        ebpf_analysis=EBPFAnalysisResult()
    )
    output.format_rich_report(report, mock_console)
    mock_format_boot.assert_called_once()
    mock_format_health.assert_called_once()
    mock_format_resource.assert_called_once()
    mock_format_log.assert_called_once()
    mock_format_dep.assert_called_once()
    mock_format_full_dep.assert_called_once()
    mock_format_ml.assert_called_once()
    mock_format_llm.assert_called_once()
    mock_format_ebpf.assert_called_once()

@patch('sysdiag_analyzer.output.format_boot_report')
@patch('sysdiag_analyzer.output.format_health_report')
@patch('sysdiag_analyzer.output.format_resource_report')
@patch('sysdiag_analyzer.output.format_log_report')
@patch('sysdiag_analyzer.output.format_dependency_report')
@patch('sysdiag_analyzer.output.format_full_dependency_report')
@patch('sysdiag_analyzer.output.format_ml_report')
@patch('sysdiag_analyzer.output.format_llm_report')
@patch('sysdiag_analyzer.output.format_ebpf_report')
def test_format_rich_report_skips_none(
    mock_format_ebpf, mock_format_llm, mock_format_ml, mock_format_full_dep, mock_format_dep,
    mock_format_log, mock_format_resource, mock_format_health, mock_format_boot,
    mock_console
):
    report = SystemReport(
        boot_analysis=BootAnalysisResult(),
        health_analysis=None,
        resource_analysis=ResourceAnalysisResult(),
        log_analysis=None,
        dependency_analysis=None,
        full_dependency_analysis=None,
        ml_analysis=None,
        llm_analysis=None,
        ebpf_analysis=None
    )
    output.format_rich_report(report, mock_console)
    mock_format_boot.assert_called_once()
    mock_format_health.assert_not_called()
    mock_format_resource.assert_called_once()
    mock_format_log.assert_not_called()
    mock_format_dep.assert_not_called()
    mock_format_full_dep.assert_not_called()
    mock_format_ml.assert_not_called()
    mock_format_llm.assert_not_called()
    mock_format_ebpf.assert_not_called()
    