# tests/test_output.py
# -*- coding: utf-8 -*-

import pytest
import datetime
import re # Import re for more robust assertions
from unittest.mock import patch, MagicMock, call, ANY
from rich.console import Console, Group
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.padding import Padding
from rich.syntax import Syntax

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
    EBPFAnalysisResult, # Added for test
    EBPFExecEvent,
    EBPFExitEvent,
    ChildProcessGroupUsage # Added for test
)

# --- Fixtures ---

@pytest.fixture
def mock_console():
    """Provides a mocked Rich Console object."""
    # Use force_terminal=True to ensure styles are applied even when capturing
    return Console(record=True, width=120, force_terminal=True)

# --- Tests for format_full_dependency_report ---
# (These tests remain unchanged)
def test_format_full_dep_report_with_cycles(mock_console):
    """Test formatting with detected cycles."""
    result = FullDependencyAnalysisResult(
        detected_cycles=[['A.service', 'B.service'], ['C.service', 'D.service', 'E.service']]
    )
    output.format_full_dependency_report(result, mock_console)
    captured_output = mock_console.export_text()

    assert "Full Dependency Graph Analysis" in captured_output
    assert "Detected 2 Dependency Cycles" in captured_output
    assert "A.service -> B.service -> A.service" in captured_output
    assert "C.service -> D.service -> E.service -> C.service" in captured_output
    assert "No dependency cycles detected" not in captured_output
    assert "Analysis Error" not in captured_output

def test_format_full_dep_report_no_cycles(mock_console):
    """Test formatting with no cycles detected."""
    result = FullDependencyAnalysisResult(detected_cycles=[])
    output.format_full_dependency_report(result, mock_console)
    captured_output = mock_console.export_text()

    assert "Full Dependency Graph Analysis" in captured_output
    assert "No dependency cycles detected" in captured_output
    assert "Detected" not in captured_output
    assert "Analysis Error" not in captured_output

def test_format_full_dep_report_analysis_error(mock_console):
    """Test formatting with a general analysis error."""
    result = FullDependencyAnalysisResult(analysis_error="Something went wrong")
    output.format_full_dependency_report(result, mock_console)
    captured_output = mock_console.export_text()

    assert "Full Dependency Graph Analysis" in captured_output
    assert "Analysis Error: Something went wrong" in captured_output
    assert "No dependency cycles detected" not in captured_output # Error takes precedence

def test_format_full_dep_report_sub_errors(mock_console):
    """Test formatting with specific fetch or build errors."""
    result = FullDependencyAnalysisResult(
        analysis_error="Top-level failure",
        dependency_fetch_error="Could not run systemctl",
        graph_build_error="Networkx failed"
    )
    output.format_full_dependency_report(result, mock_console)
    captured_output = mock_console.export_text()

    assert "Full Dependency Graph Analysis" in captured_output
    assert "Analysis Error: Top-level failure" in captured_output
    assert "Fetch Error: Could not run systemctl" in captured_output
    assert "Graph Build Error: Networkx failed" in captured_output

def test_format_full_dep_report_none_input(mock_console):
    """Test formatting when the input result is None."""
    output.format_full_dependency_report(None, mock_console)
    captured_output = mock_console.export_text()
    # Should print nothing
    assert captured_output.strip() == ""


@patch('sysdiag_analyzer.output.MAX_CYCLES_TO_SHOW', 2) # Temporarily reduce limit for test
def test_format_full_dep_report_cycle_limit(mock_console):
    """Test formatting with more cycles than the display limit."""
    result = FullDependencyAnalysisResult(
        detected_cycles=[['A', 'B'], ['C', 'D'], ['E', 'F']]
    )
    output.format_full_dependency_report(result, mock_console)
    captured_output = mock_console.export_text()

    assert "Detected 3 Dependency Cycles" in captured_output
    assert "A -> B -> A" in captured_output
    assert "C -> D -> C" in captured_output
    assert "E -> F -> E" not in captured_output # Should be omitted
    assert f"... ({len(result.detected_cycles) - 2} more cycles omitted) ..." in captured_output

# --- Tests for format_llm_report (Phase 9) ---

def test_format_llm_report_success(mock_console):
    """Test formatting a successful LLM result."""
    result = LLMAnalysisResult(
        synthesis="## LLM Synthesis\n\nThis is the analysis.\n- Point 1\n- Point 2",
        provider_used="ollama",
        model_used="test-model",
        prompt_token_count=100,
        completion_token_count=50
    )
    output.format_llm_report(result, mock_console)
    captured_output = mock_console.export_text()

    assert "LLM Synthesis & Recommendations" in captured_output
    assert "Provider: ollama" in captured_output
    assert "Model: test-model" in captured_output
    assert "Prompt Tokens: 100" in captured_output
    assert "Completion Tokens: 50" in captured_output
    # Check for Markdown content (exact rendering depends on Rich version)
    assert "LLM Synthesis" in captured_output
    assert "This is the analysis." in captured_output
    assert "Point 1" in captured_output
    assert "Analysis Error" not in captured_output

def test_format_llm_report_error(mock_console):
    """Test formatting an LLM result with an error."""
    result = LLMAnalysisResult(
        error="LLM failed to load model.",
        provider_used="ollama",
        model_used="bad-model"
    )
    output.format_llm_report(result, mock_console)
    captured_output = mock_console.export_text()

    assert "LLM Synthesis & Recommendations" in captured_output
    assert "LLM Analysis Error: LLM failed to load model." in captured_output
    assert "Provider: ollama" in captured_output # Metadata still shown
    assert "Model: bad-model" in captured_output
    # assert "LLM Synthesis" not in captured_output # Removed redundant assertion

def test_format_llm_report_no_synthesis(mock_console):
    """Test formatting when LLM runs but produces no synthesis."""
    result = LLMAnalysisResult(
        synthesis=None, # Explicitly None
        provider_used="ollama",
        model_used="test-model",
        error=None # No error reported
    )
    output.format_llm_report(result, mock_console)
    captured_output = mock_console.export_text()

    assert "LLM Synthesis & Recommendations" in captured_output
    assert "LLM did not produce a synthesis." in captured_output
    assert "Analysis Error" not in captured_output

def test_format_llm_report_none_input(mock_console):
    """Test formatting when the input result is None."""
    output.format_llm_report(None, mock_console)
    captured_output = mock_console.export_text()
    # Should print nothing
    assert captured_output.strip() == ""

# --- Tests for format_ebpf_report (Phase 10) ---

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
            EBPFExitEvent(timestamp_ns=ts3_ns + 1000000, pid=1001, ppid=1, comm="bash", cgroup_id=12345, exit_code=1), # Example non-zero exit
        ]
    )
    output.format_ebpf_report(result, mock_console)
    # FIX: Check recorded *styled* output for summary line and specific content
    captured_output_styled = mock_console.export_text(styles=True)
    captured_output_no_styles = mock_console.export_text(styles=False) # Keep for some checks

    # Check for summary line in styled output
    assert "Events Captured: Execs=2, Exits=2" in captured_output_styled
    # FIX: Check for specific content in styled output (more reliable than plain)
    assert "/bin/bash" in captured_output_styled
    assert "sleep" in captured_output_styled
    assert "1001" in captured_output_styled
    assert "1002" in captured_output_styled

    # Check for exit codes using regex (remains useful on plain text)
    assert re.search(r"1002\s+│\s+1001\s+│\s+sleep\s+│\s+0\s+│", captured_output_no_styles)
    assert re.search(r"1001\s+│\s+1\s+│\s+bash\s+│\s+1\s+│", captured_output_no_styles)
    # Check styled output for colored exit code
    assert "[bold red]1[/]" in captured_output_styled

    assert "Error" not in captured_output_no_styles


def test_format_ebpf_report_no_events(mock_console):
    """Test formatting eBPF results when no events were captured."""
    result = EBPFAnalysisResult(exec_events=[], exit_events=[])
    output.format_ebpf_report(result, mock_console)
    captured_output = mock_console.export_text()

    # Check for the specific summary string in the output
    assert "Events Captured: Execs=0, Exits=0" in captured_output
    assert "No eBPF process events captured" in captured_output
    assert "Recent Process Executions" not in captured_output # Tables shouldn't be printed
    assert "Recent Process Exits" not in captured_output
    assert "Error" not in captured_output

def test_format_ebpf_report_with_error(mock_console):
    """Test formatting eBPF results when an analysis error occurred."""
    result = EBPFAnalysisResult(error="BPF program load failed: insufficient memory.")
    output.format_ebpf_report(result, mock_console)
    captured_output = mock_console.export_text()

    assert "eBPF Analysis Error: BPF program load failed: insufficient memory." in captured_output
    assert "Events Captured" in captured_output # Summary still shown
    assert "Recent Process Executions" not in captured_output # No tables if error
    assert "Recent Process Exits" not in captured_output

def test_format_ebpf_report_none_input(mock_console):
    """Test formatting when the input result is None."""
    output.format_ebpf_report(None, mock_console)
    captured_output = mock_console.export_text()
    # Should print nothing
    assert captured_output.strip() == ""

# --- Tests for format_resource_report (incl. Child Processes) ---

def test_format_resource_report_with_child_procs(mock_console):
    """Test resource formatting including the child process group table."""
    result = ResourceAnalysisResult(
        child_process_groups=[
            ChildProcessGroupUsage(command_name="python3", parent_unit="my_app.service", process_count=5, pids=[101, 102, 103], aggregated_cpu_percent=25.5, aggregated_memory_bytes=200*1024*1024),
            ChildProcessGroupUsage(command_name="nginx", parent_unit="nginx.service", process_count=2, pids=[201, 202], aggregated_cpu_percent=5.1, aggregated_memory_bytes=50*1024*1024),
        ]
        # Include some system/unit data for completeness if needed
    )
    output.format_resource_report(result, mock_console)
    captured_output = mock_console.export_text()

    assert "Resource Analysis" in captured_output
    assert "Child Process Group Usage" in captured_output
    # Check table headers/content
    assert "Command Name" in captured_output
    assert "Parent Unit" in captured_output
    assert "Aggr. CPU %" in captured_output
    assert "Aggr. Memory" in captured_output
    assert "python3" in captured_output
    assert "my_app.service" in captured_output
    assert "5" in captured_output # Process count
    assert "25.5%" in captured_output
    assert "200.0 MiB" in captured_output
    assert "101, 102, 103..." in captured_output # Example PIDs (check for ellipsis)
    assert "nginx" in captured_output


# --- Tests for format_rich_report integration ---

@patch('sysdiag_analyzer.output.format_boot_report')
@patch('sysdiag_analyzer.output.format_health_report')
@patch('sysdiag_analyzer.output.format_resource_report')
@patch('sysdiag_analyzer.output.format_log_report')
@patch('sysdiag_analyzer.output.format_dependency_report')
@patch('sysdiag_analyzer.output.format_full_dependency_report')
@patch('sysdiag_analyzer.output.format_ml_report')
@patch('sysdiag_analyzer.output.format_llm_report')
@patch('sysdiag_analyzer.output.format_ebpf_report') # Added Phase 10 mock
def test_format_rich_report_calls_all_formatters(
    mock_format_ebpf, mock_format_llm, mock_format_ml, mock_format_full_dep, mock_format_dep,
    mock_format_log, mock_format_resource, mock_format_health, mock_format_boot,
    mock_console
):
    """Test that format_rich_report calls all formatters when data is present."""
    # Create mock result objects for all sections
    mock_boot_result = BootAnalysisResult()
    mock_health_result = HealthAnalysisResult()
    mock_resource_result = ResourceAnalysisResult()
    mock_log_result = LogAnalysisResult()
    mock_dep_result = DependencyAnalysisResult()
    mock_graph_result = FullDependencyAnalysisResult()
    mock_ml_result = MLAnalysisResult()
    mock_llm_result = LLMAnalysisResult()
    mock_ebpf_result = EBPFAnalysisResult() # Phase 10

    report = SystemReport(
        boot_analysis=mock_boot_result,
        health_analysis=mock_health_result,
        resource_analysis=mock_resource_result,
        log_analysis=mock_log_result,
        dependency_analysis=mock_dep_result,
        full_dependency_analysis=mock_graph_result,
        ml_analysis=mock_ml_result,
        llm_analysis=mock_llm_result,
        ebpf_analysis=mock_ebpf_result # Phase 10
    )

    output.format_rich_report(report, mock_console)

    # Assert all formatters were called once with their respective data
    mock_format_boot.assert_called_once_with(mock_boot_result, mock_console)
    mock_format_health.assert_called_once_with(mock_health_result, mock_console)
    mock_format_resource.assert_called_once_with(mock_resource_result, mock_console)
    mock_format_log.assert_called_once_with(mock_log_result, mock_console)
    mock_format_dep.assert_called_once_with(mock_dep_result, mock_console)
    mock_format_full_dep.assert_called_once_with(mock_graph_result, mock_console)
    mock_format_ml.assert_called_once_with(mock_ml_result, mock_console)
    mock_format_llm.assert_called_once_with(mock_llm_result, mock_console)
    mock_format_ebpf.assert_called_once_with(mock_ebpf_result, mock_console) # Phase 10


@patch('sysdiag_analyzer.output.format_boot_report')
@patch('sysdiag_analyzer.output.format_health_report')
@patch('sysdiag_analyzer.output.format_resource_report')
@patch('sysdiag_analyzer.output.format_log_report')
@patch('sysdiag_analyzer.output.format_dependency_report')
@patch('sysdiag_analyzer.output.format_full_dependency_report')
@patch('sysdiag_analyzer.output.format_ml_report')
@patch('sysdiag_analyzer.output.format_llm_report')
@patch('sysdiag_analyzer.output.format_ebpf_report') # Added Phase 10 mock
def test_format_rich_report_skips_none(
    mock_format_ebpf, mock_format_llm, mock_format_ml, mock_format_full_dep, mock_format_dep,
    mock_format_log, mock_format_resource, mock_format_health, mock_format_boot,
    mock_console
):
    """Test that format_rich_report skips formatters when data is None."""
    # Create a report with some sections explicitly None
    report = SystemReport(
        boot_analysis=BootAnalysisResult(), # Present
        health_analysis=None, # Absent
        resource_analysis=ResourceAnalysisResult(), # Present
        log_analysis=None, # Absent
        dependency_analysis=None, # Absent
        full_dependency_analysis=None, # Absent
        ml_analysis=None, # Absent
        llm_analysis=None, # Absent
        ebpf_analysis=None # Absent (Phase 10)
    )

    output.format_rich_report(report, mock_console)

    # Assert formatters were called only for non-None data
    mock_format_boot.assert_called_once()
    mock_format_health.assert_not_called()
    mock_format_resource.assert_called_once()
    mock_format_log.assert_not_called()
    mock_format_dep.assert_not_called()
    mock_format_full_dep.assert_not_called()
    mock_format_ml.assert_not_called()
    mock_format_llm.assert_not_called()
    mock_format_ebpf.assert_not_called() # Phase 10
