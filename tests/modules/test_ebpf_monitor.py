# -*- coding: utf-8 -*-
# Phase 10: Tests for eBPF Monitor module

import pytest
import time
import ctypes as ct # Import ctypes
from unittest.mock import patch, MagicMock, call
import logging

# Conditional import for BCC
try:
    from bcc import BPF
    HAS_BCC_FOR_TEST = True
except ImportError:
    HAS_BCC_FOR_TEST = False
    BPF = None # type: ignore

# Module to test
from sysdiag_analyzer.modules import ebpf_monitor
from sysdiag_analyzer.datatypes import EBPFAnalysisResult, EBPFExecEvent, EBPFExitEvent

# Marker for tests requiring BCC and root
pytestmark_ebpf = pytest.mark.skipif(not HAS_BCC_FOR_TEST or not ebpf_monitor.HAS_BCC, reason="Requires bcc library")
# Add needs_root marker if tests actually interact with kernel BPF subsystem
# pytestmark_ebpf = pytest.mark.needs_ebpf


@pytestmark_ebpf
@patch('sysdiag_analyzer.modules.ebpf_monitor.BPF') # Mock the BPF class
def test_ebpf_collector_init_start_stop(mock_bpf_cls):
    """Test basic initialization, start, and stop flow."""
    mock_bpf_instance = MagicMock()
    mock_perf_buffer_exec = MagicMock()
    mock_perf_buffer_exit = MagicMock()
    mock_bpf_instance.__getitem__.side_effect = lambda key: {
        "exec_events": mock_perf_buffer_exec,
        "exit_events": mock_perf_buffer_exit,
    }.get(key)
    mock_bpf_cls.return_value = mock_bpf_instance

    collector = ebpf_monitor.EBPFCollector()
    assert collector.bpf is None
    assert not collector._running
    assert collector.exec_events == [] # Check initial state
    assert collector.exit_events == []

    # Test Start
    collector.start()
    assert collector.bpf == mock_bpf_instance
    assert collector._running
    mock_bpf_cls.assert_called_once_with(text=ebpf_monitor.BPF_PROGRAM)
    mock_perf_buffer_exec.open_perf_buffer.assert_called_once()
    mock_perf_buffer_exit.open_perf_buffer.assert_called_once()

    # Test Stop
    result = collector.stop()
    assert isinstance(result, EBPFAnalysisResult)
    assert not collector._running
    assert collector.bpf is None # Should be cleaned up
    mock_bpf_instance.cleanup.assert_called_once()
    # Check final poll was called
    mock_bpf_instance.perf_buffer_poll.assert_called_with(timeout=200)
    # Result should contain events collected (empty in this basic test)
    assert result.exec_events == []
    assert result.exit_events == []


@pytestmark_ebpf
@patch('sysdiag_analyzer.modules.ebpf_monitor.BPF')
def test_ebpf_collector_start_failure(mock_bpf_cls):
    """Test handling of failure during BPF program loading."""
    mock_bpf_cls.side_effect = Exception("BPF Load Error")

    with pytest.raises(RuntimeError, match="eBPF initialization failed: BPF Load Error"):
        collector = ebpf_monitor.EBPFCollector()
        collector.start()

    # Ensure collector state is clean after failed start attempt
    # Need to instantiate collector outside the context where start raises
    collector = ebpf_monitor.EBPFCollector()
    assert collector.bpf is None
    assert not collector._running


@pytestmark_ebpf
@patch('sysdiag_analyzer.modules.ebpf_monitor.BPF') # Mock BPF to avoid actual loading
def test_handle_exec_event_success(mock_bpf_cls, caplog):
    """Test handling a valid exec event."""
    collector = ebpf_monitor.EBPFCollector()
    # Setup a mock C structure for the event data
    mock_c_event = ebpf_monitor.ExecData()
    mock_c_event.timestamp_ns = 1234567890000000000
    mock_c_event.pid = 1001
    mock_c_event.ppid = 1000
    mock_c_event.cgroup_id = 9876543210
    mock_c_event.comm = b"test_command"
    mock_c_event.filename = b"/usr/bin/test_command"

    # Create a pointer to the mock structure
    event_ptr = ct.pointer(mock_c_event)
    event_data = ct.cast(event_ptr, ct.c_void_p)

    # Call the handler
    with caplog.at_level(logging.DEBUG, logger='sysdiag_analyzer.modules.ebpf_monitor.ebpf_detail'):
         collector._handle_exec_event(cpu=0, data=event_data.value, size=ct.sizeof(mock_c_event))

    # Assertions
    assert len(collector.exec_events) == 1
    event = collector.exec_events[0]
    assert isinstance(event, EBPFExecEvent)
    assert event.timestamp_ns == 1234567890000000000
    assert event.pid == 1001
    assert event.ppid == 1000
    assert event.cgroup_id == 9876543210
    assert event.comm == "test_command"
    assert event.filename == "/usr/bin/test_command"
    # Check logs
    assert "eBPF EXEC Event: PID=1001, PPID=1000, CG=9876543210, COMM=test_command, FILE=/usr/bin/test_command" in caplog.text


@pytestmark_ebpf
@patch('sysdiag_analyzer.modules.ebpf_monitor.BPF') # Mock BPF to avoid actual loading
def test_handle_exit_event_success(mock_bpf_cls, caplog):
    """Test handling a valid exit event."""
    collector = ebpf_monitor.EBPFCollector()
    # Setup a mock C structure for the event data
    mock_c_event = ebpf_monitor.ExitData()
    mock_c_event.timestamp_ns = 1234567900000000000
    mock_c_event.pid = 1001
    mock_c_event.ppid = 1000
    mock_c_event.cgroup_id = 9876543210
    mock_c_event.comm = b"test_command"
    mock_c_event.exit_code = 1

    # Create a pointer to the mock structure
    event_ptr = ct.pointer(mock_c_event)
    event_data = ct.cast(event_ptr, ct.c_void_p)

    # Call the handler
    with caplog.at_level(logging.DEBUG, logger='sysdiag_analyzer.modules.ebpf_monitor.ebpf_detail'):
        collector._handle_exit_event(cpu=0, data=event_data.value, size=ct.sizeof(mock_c_event))

    # Assertions
    assert len(collector.exit_events) == 1
    event = collector.exit_events[0]
    assert isinstance(event, EBPFExitEvent)
    assert event.timestamp_ns == 1234567900000000000
    assert event.pid == 1001
    assert event.ppid == 1000
    assert event.cgroup_id == 9876543210
    assert event.comm == "test_command"
    assert event.exit_code == 1
    # Check logs
    assert "eBPF EXIT Event: PID=1001, PPID=1000, CG=9876543210, COMM=test_command, CODE=1" in caplog.text


@pytestmark_ebpf
@patch('sysdiag_analyzer.modules.ebpf_monitor.BPF') # Mock BPF to avoid actual loading
def test_handle_event_exception(mock_bpf_cls, caplog):
    """Test exception handling within event handlers."""
    collector = ebpf_monitor.EBPFCollector()

    # Simulate bad data (e.g., wrong type) causing an exception
    bad_data_ptr = ct.c_void_p() # Null pointer

    # Call exec handler
    collector._handle_exec_event(cpu=0, data=bad_data_ptr.value, size=1)
    assert "Error processing eBPF exec event" in caplog.text
    assert len(collector.exec_events) == 0 # Ensure event wasn't added

    caplog.clear() # Clear logs for next check

    # Call exit handler
    collector._handle_exit_event(cpu=0, data=bad_data_ptr.value, size=1)
    assert "Error processing eBPF exit event" in caplog.text
    assert len(collector.exit_events) == 0 # Ensure event wasn't added


# TODO: Add integration test for run_ebpf_analysis function if needed
# This would mock the EBPFCollector class itself, time.sleep, etc.
# Example structure:
# @pytestmark_ebpf
# @patch('sysdiag_analyzer.modules.ebpf_monitor.time.sleep')
# @patch('sysdiag_analyzer.modules.ebpf_monitor.EBPFCollector')
# def test_run_ebpf_analysis_integration(mock_collector_cls, mock_sleep):
#     mock_collector_instance = MagicMock()
#     mock_collector_instance.stop.return_value = EBPFAnalysisResult(exec_events=[...]) # Mock some return data
#     mock_collector_cls.return_value = mock_collector_instance
#
#     duration = 0.2 # Use short duration for test
#     result = ebpf_monitor.run_ebpf_analysis(duration_sec=duration)
#
#     mock_collector_cls.assert_called_once()
#     mock_collector_instance.start.assert_called_once()
#     # Check poll was called multiple times (depends on sleep duration)
#     mock_collector_instance.poll_events.assert_called()
#     mock_collector_instance.stop.assert_called_once()
#     # Assert result contains the mocked data
#     assert len(result.exec_events) > 0
#     # Assert sleep was called
#     mock_sleep.assert_called()
