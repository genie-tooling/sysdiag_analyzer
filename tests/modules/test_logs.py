import pytest
import json
import datetime
import re
from unittest.mock import patch, MagicMock, ANY

# Module to test
from sysdiag_analyzer.modules import logs
from sysdiag_analyzer.datatypes import LogPatternInfo

# --- Constants ---
T_BASE = 1700000000 # Base timestamp in seconds
T_USEC_1 = T_BASE * 1_000_000 + 100000
T_USEC_2 = T_BASE * 1_000_000 + 200000
T_USEC_3 = T_BASE * 1_000_000 + 300000
T_USEC_4 = T_BASE * 1_000_000 + 400000
T_USEC_5 = T_BASE * 1_000_000 + 500000
T_USEC_6 = T_BASE * 1_000_000 + 600000
T_USEC_7 = T_BASE * 1_000_000 + 700000
T_USEC_8 = T_BASE * 1_000_000 + 800000
T_USEC_9 = T_BASE * 1_000_000 + 900000
T_USEC_10 = T_BASE * 1_000_000 + 1000000

DT_1 = datetime.datetime.fromtimestamp(T_USEC_1 / 1e6, tz=datetime.timezone.utc)
DT_2 = datetime.datetime.fromtimestamp(T_USEC_2 / 1e6, tz=datetime.timezone.utc)
DT_3 = datetime.datetime.fromtimestamp(T_USEC_3 / 1e6, tz=datetime.timezone.utc)
DT_4 = datetime.datetime.fromtimestamp(T_USEC_4 / 1e6, tz=datetime.timezone.utc)
DT_5 = datetime.datetime.fromtimestamp(T_USEC_5 / 1e6, tz=datetime.timezone.utc)
DT_6 = datetime.datetime.fromtimestamp(T_USEC_6 / 1e6, tz=datetime.timezone.utc)
DT_7 = datetime.datetime.fromtimestamp(T_USEC_7 / 1e6, tz=datetime.timezone.utc)
DT_8 = datetime.datetime.fromtimestamp(T_USEC_8 / 1e6, tz=datetime.timezone.utc)
DT_9 = datetime.datetime.fromtimestamp(T_USEC_9 / 1e6, tz=datetime.timezone.utc)
DT_10 = datetime.datetime.fromtimestamp(T_USEC_10 / 1e6, tz=datetime.timezone.utc)

# --- Mock Data ---

# Native-style entries (list of dicts)
MOCK_NATIVE_ENTRIES = [
    # Priority 2 (CRIT) - Should be included by default (>=4) is false, but included if min_prio=2
    {"PRIORITY": "2", "MESSAGE": "Kernel panic - not syncing: Fatal exception", "_SYSTEMD_UNIT": "kernel", "_PID": "1", "__REALTIME_TIMESTAMP": T_USEC_1, "date": DT_1},
    # Priority 3 (ERR) - Should be included by default (>=4) is false, but included if min_prio=3
    {"PRIORITY": "3", "MESSAGE": "segfault at 7f... ip 0000... sp 0000... error 4", "_SYSTEMD_UNIT": "app.service", "_PID": "1234", "__REALTIME_TIMESTAMP": T_USEC_2, "date": DT_2},
    # Priority 4 (WARNING) - Should be included by default (>=4)
    {"PRIORITY": "4", "MESSAGE": "task systemd-udevd:123 blocked for more than 120 seconds.", "_SYSTEMD_UNIT": "kernel", "_PID": "0", "__REALTIME_TIMESTAMP": T_USEC_3, "date": DT_3},
    # Priority 4 (WARNING) - Should be included
    {"PRIORITY": "4", "MESSAGE": "I/O error, dev sda, sector 12345", "_SYSTEMD_UNIT": "kernel", "_PID": "0", "__REALTIME_TIMESTAMP": T_USEC_4, "date": DT_4},
    # Priority 5 (NOTICE) - Should be ignored by default (>=4)
    {"PRIORITY": "5", "MESSAGE": "System startup complete.", "_SYSTEMD_UNIT": "systemd", "_PID": "1", "__REALTIME_TIMESTAMP": T_USEC_5, "date": DT_5},
    # Priority 6 (INFO) - Should be ignored by default (>=4)
    {"PRIORITY": "6", "MESSAGE": "User login successful.", "_SYSTEMD_UNIT": "login.service", "_PID": "5678", "__REALTIME_TIMESTAMP": T_USEC_6, "date": DT_6},
    # Priority 3 (ERR) - OOM Killer
    {"PRIORITY": "3", "MESSAGE": "oom-killer: Killed process 9999 (oom_app)", "_SYSTEMD_UNIT": "kernel", "_PID": "0", "__REALTIME_TIMESTAMP": T_USEC_7, "date": DT_7},
    # Priority 4 (WARNING) - Another I/O error
    {"PRIORITY": "4", "MESSAGE": "Input/output error on /dev/sdb", "_SYSTEMD_UNIT": "kernel", "_PID": "0", "__REALTIME_TIMESTAMP": T_USEC_8, "date": DT_8},
    # Priority 3 (ERR) - Another segfault
    {"PRIORITY": "3", "MESSAGE": "app.service[4321]: segfault at 0 ip 0000... sp 0000... error 6", "_SYSTEMD_UNIT": "app.service", "_PID": "4321", "__REALTIME_TIMESTAMP": T_USEC_9, "date": DT_9},
    # Priority 7 (DEBUG) - Should be ignored by default
    {"PRIORITY": "7", "MESSAGE": "Debugging message value=10", "_SYSTEMD_UNIT": "debug.service", "_PID": "1111", "__REALTIME_TIMESTAMP": T_USEC_10, "date": DT_10},
]

# Fallback-style JSON output (lines)
MOCK_JOURNALCTL_JSON_OUTPUT_PRIO_4 = f"""
{{"PRIORITY": "4", "MESSAGE": "task systemd-udevd:123 blocked for more than 120 seconds.", "_SYSTEMD_UNIT": "kernel", "_PID": "0", "__REALTIME_TIMESTAMP": "{T_USEC_3}"}}
{{"PRIORITY": "4", "MESSAGE": "I/O error, dev sda, sector 12345", "_SYSTEMD_UNIT": "kernel", "_PID": "0", "__REALTIME_TIMESTAMP": "{T_USEC_4}"}}
{{"PRIORITY": "3", "MESSAGE": "segfault at 7f... ip 0000... sp 0000... error 4", "_SYSTEMD_UNIT": "app.service", "_PID": "1234", "__REALTIME_TIMESTAMP": "{T_USEC_2}"}}
{{"PRIORITY": "2", "MESSAGE": "Kernel panic - not syncing: Fatal exception", "_SYSTEMD_UNIT": "kernel", "_PID": "1", "__REALTIME_TIMESTAMP": "{T_USEC_1}"}}
{{"PRIORITY": "3", "MESSAGE": "oom-killer: Killed process 9999 (oom_app)", "_SYSTEMD_UNIT": "kernel", "_PID": "0", "__REALTIME_TIMESTAMP": "{T_USEC_7}"}}
{{"PRIORITY": "4", "MESSAGE": "Input/output error on /dev/sdb", "_SYSTEMD_UNIT": "kernel", "_PID": "0", "__REALTIME_TIMESTAMP": "{T_USEC_8}"}}
{{"PRIORITY": "3", "MESSAGE": "app.service[4321]: segfault at 0 ip 0000... sp 0000... error 6", "_SYSTEMD_UNIT": "app.service", "_PID": "4321", "__REALTIME_TIMESTAMP": "{T_USEC_9}"}}
"""

MOCK_JOURNALCTL_JSON_OUTPUT_PRIO_2 = f"""
{{"PRIORITY": "2", "MESSAGE": "Kernel panic - not syncing: Fatal exception", "_SYSTEMD_UNIT": "kernel", "_PID": "1", "__REALTIME_TIMESTAMP": "{T_USEC_1}"}}
{{"PRIORITY": "3", "MESSAGE": "segfault at 7f... ip 0000... sp 0000... error 4", "_SYSTEMD_UNIT": "app.service", "_PID": "1234", "__REALTIME_TIMESTAMP": "{T_USEC_2}"}}
{{"PRIORITY": "3", "MESSAGE": "oom-killer: Killed process 9999 (oom_app)", "_SYSTEMD_UNIT": "kernel", "_PID": "0", "__REALTIME_TIMESTAMP": "{T_USEC_7}"}}
{{"PRIORITY": "3", "MESSAGE": "app.service[4321]: segfault at 0 ip 0000... sp 0000... error 6", "_SYSTEMD_UNIT": "app.service", "_PID": "4321", "__REALTIME_TIMESTAMP": "{T_USEC_9}"}}
"""

MOCK_JOURNALCTL_JSON_OUTPUT_NO_ISSUES = f"""
{{"PRIORITY": "4", "MESSAGE": "Normal warning message 1", "_SYSTEMD_UNIT": "some.service", "_PID": "100", "__REALTIME_TIMESTAMP": "{T_USEC_3}"}}
{{"PRIORITY": "4", "MESSAGE": "Normal warning message 2", "_SYSTEMD_UNIT": "other.service", "_PID": "200", "__REALTIME_TIMESTAMP": "{T_USEC_4}"}}
"""

MOCK_JOURNALCTL_JSON_INVALID = """
{"PRIORITY": "4", "MESSAGE": "Good line"}
this is not json
{"PRIORITY": "3", "MESSAGE": "Another good line"}
"""

# Expected results for default priority (4)
EXPECTED_PATTERNS_PRIO_4 = [
    LogPatternInfo(pattern_type='Error', pattern_key='segfault', count=2, level='ERR', example_messages=ANY),
    LogPatternInfo(pattern_type='Warning', pattern_key='i/o-error', count=2, level='WARNING', example_messages=ANY),
    LogPatternInfo(pattern_type='OOM', pattern_key='oom-killer', count=1, level='ERR', example_messages=ANY),
    LogPatternInfo(pattern_type='Warning', pattern_key='task-blocked', count=1, level='WARNING', example_messages=ANY),
    LogPatternInfo(pattern_type='Error', pattern_key='kernel-panic', count=1, level='CRIT', example_messages=ANY),
]
EXPECTED_TOTAL_ENTRIES_NATIVE = 10 # Total read before filtering
EXPECTED_ANALYZED_ENTRIES_PRIO_4 = 7 # Entries with prio <= 4

# Expected results for priority 2 (FIXED: Only prio 0, 1, 2)
EXPECTED_PATTERNS_PRIO_2 = [
    LogPatternInfo(pattern_type='Error', pattern_key='kernel-panic', count=1, level='CRIT', example_messages=ANY),
]
EXPECTED_ANALYZED_ENTRIES_PRIO_2 = 1 # Entries with prio <= 2

# --- Fixtures ---

@pytest.fixture
def mock_cysystemd_reader():
    """Mocks the cysystemd JournalReader."""
    if not logs.HAS_CYSYSTEMD:
        yield None
        return

    mock_reader_instance = MagicMock(spec=logs.JournalReader)
    mock_records = []
    # Prepare mock records (need data and date attributes)
    for entry in MOCK_NATIVE_ENTRIES:
        record = MagicMock()
        record.data = entry
        record.date = entry['date']
        mock_records.append(record)

    # Simulate iteration
    mock_reader_instance.__iter__.return_value = iter(mock_records)

    with patch('sysdiag_analyzer.modules.logs.JournalReader', return_value=mock_reader_instance) as mock_cls:
        yield mock_reader_instance

@pytest.fixture
def mock_run_subprocess_logs():
    """Mocks utils.run_subprocess for log analysis."""
    with patch('sysdiag_analyzer.modules.logs.run_subprocess') as mock_run:
        def side_effect(command):
            cmd_str = " ".join(command)
            if "journalctl" not in cmd_str:
                return (False, "", "Unexpected command")

            # Default success, override based on args
            success = True
            stdout = ""
            stderr = ""

            # Extract options
            boot_match = re.search(r"-b(-?\d+)", cmd_str)
            prio_match = re.search(r"-p(\d+)\.\.0", cmd_str)
            boot_offset = int(boot_match.group(1)) if boot_match else 0
            min_priority = int(prio_match.group(1)) if prio_match else logs.DEFAULT_ANALYSIS_LEVEL

            # Simulate different outputs based on priority/boot offset
            if boot_offset == -99: # Test failure case
                success = False
                stderr = "journalctl command failed test"
                stdout = ""
            elif boot_offset == -98: # Test invalid JSON case
                success = True
                stdout = MOCK_JOURNALCTL_JSON_INVALID
                stderr = ""
            elif boot_offset == -97: # Test no issues case
                success = True
                stdout = MOCK_JOURNALCTL_JSON_OUTPUT_NO_ISSUES
                stderr = ""
            elif min_priority <= 2:
                stdout = MOCK_JOURNALCTL_JSON_OUTPUT_PRIO_2
            elif min_priority <= 4:
                stdout = MOCK_JOURNALCTL_JSON_OUTPUT_PRIO_4
            else: # Higher priority means fewer messages
                stdout = MOCK_JOURNALCTL_JSON_OUTPUT_NO_ISSUES # Simulate fewer messages

            return (success, stdout, stderr)

        mock_run.side_effect = side_effect
        yield mock_run

# --- Helper Function ---
def assert_patterns_match(actual: list[LogPatternInfo], expected: list[LogPatternInfo]):
    """Compares two lists of LogPatternInfo, ignoring example messages and order."""
    assert len(actual) == len(expected), f"Expected {len(expected)} patterns, got {len(actual)}"
    # Compare sets of tuples (type, key, count, level)
    actual_set = set((p.pattern_type, p.pattern_key, p.count, p.level) for p in actual)
    expected_set = set((p.pattern_type, p.pattern_key, p.count, p.level) for p in expected)
    assert actual_set == expected_set, f"Pattern sets differ.\nActual: {actual_set}\nExpected: {expected_set}"

# --- Test Cases ---

# Scenario 1: Native Path Success (cysystemd)
@pytest.mark.skipif(not logs.HAS_CYSYSTEMD, reason="cysystemd not installed")
def test_analyze_logs_native_success_default_prio(mock_cysystemd_reader):
    result = logs.analyze_general_logs(min_priority=4) # Default prio

    assert result.analysis_error is None
    assert result.log_source == "cysystemd"
    # Native reads all entries, filtering happens in loop
    assert result.total_entries_analyzed == EXPECTED_TOTAL_ENTRIES_NATIVE
    assert_patterns_match(result.detected_patterns, EXPECTED_PATTERNS_PRIO_4)
    # Check example messages are populated (basic check)
    for pattern in result.detected_patterns:
        assert len(pattern.example_messages) > 0
        assert len(pattern.example_messages) <= logs.MAX_EXAMPLE_MESSAGES

@pytest.mark.skipif(not logs.HAS_CYSYSTEMD, reason="cysystemd not installed")
def test_analyze_logs_native_success_low_prio(mock_cysystemd_reader):
    result = logs.analyze_general_logs(min_priority=2) # Lower prio (CRIT)

    assert result.analysis_error is None
    assert result.log_source == "cysystemd"
    assert result.total_entries_analyzed == EXPECTED_TOTAL_ENTRIES_NATIVE
    # Corrected expectation: only prio 2 (kernel-panic) should match
    assert_patterns_match(result.detected_patterns, EXPECTED_PATTERNS_PRIO_2)

@pytest.mark.skipif(not logs.HAS_CYSYSTEMD, reason="cysystemd not installed")
def test_analyze_logs_native_entry_limit(mock_cysystemd_reader):
    # Reduce limit for testing
    with patch('sysdiag_analyzer.modules.logs.MAX_ENTRIES_TO_ANALYZE', 3):
        result = logs.analyze_general_logs(min_priority=7) # Include all priorities for count

    assert "Reached entry limit (3)" in (result.analysis_error or "")
    assert result.total_entries_analyzed == 3
    # Patterns will be based on the first 3 entries only
    assert len(result.detected_patterns) <= 3

# Scenario 2: Fallback Path Success (journalctl)
@patch('sysdiag_analyzer.modules.logs.HAS_NATIVE_JOURNAL', False)
def test_analyze_logs_fallback_success_default_prio(mock_run_subprocess_logs):
    result = logs.analyze_general_logs(min_priority=4) # Default prio

    assert result.analysis_error is None
    assert result.log_source == "journalctl"
    # Fallback total_entries is based on lines returned by journalctl (already filtered)
    assert result.total_entries_analyzed == len(MOCK_JOURNALCTL_JSON_OUTPUT_PRIO_4.strip().splitlines())
    assert_patterns_match(result.detected_patterns, EXPECTED_PATTERNS_PRIO_4)
    mock_run_subprocess_logs.assert_called_once()
    assert "-p4..0" in " ".join(mock_run_subprocess_logs.call_args.args[0])

@patch('sysdiag_analyzer.modules.logs.HAS_NATIVE_JOURNAL', False)
def test_analyze_logs_fallback_success_low_prio(mock_run_subprocess_logs):
    result = logs.analyze_general_logs(min_priority=2) # Lower prio

    assert result.analysis_error is None
    assert result.log_source == "journalctl"
    # Mock returns prio 2 data when asked for prio 2
    assert result.total_entries_analyzed == len(MOCK_JOURNALCTL_JSON_OUTPUT_PRIO_2.strip().splitlines())
    # Fallback output for prio 2 contains prio 3 messages as well, so expect more patterns
    # Let's define the expected patterns based on MOCK_JOURNALCTL_JSON_OUTPUT_PRIO_2
    expected_fallback_prio_2 = [
        LogPatternInfo(pattern_type='Error', pattern_key='segfault', count=2, level='ERR', example_messages=ANY),
        LogPatternInfo(pattern_type='OOM', pattern_key='oom-killer', count=1, level='ERR', example_messages=ANY),
        LogPatternInfo(pattern_type='Error', pattern_key='kernel-panic', count=1, level='CRIT', example_messages=ANY),
    ]
    assert_patterns_match(result.detected_patterns, expected_fallback_prio_2)
    mock_run_subprocess_logs.assert_called_once()
    assert "-p2..0" in " ".join(mock_run_subprocess_logs.call_args.args[0])

# Scenario 3: Native Error -> Fallback Success
@pytest.mark.skipif(not logs.HAS_CYSYSTEMD, reason="cysystemd not installed")
@patch('sysdiag_analyzer.modules.logs.JournalReader') # Patch the class directly
def test_analyze_logs_native_error_fallback(mock_reader_cls, mock_run_subprocess_logs):
    # Make native reader fail
    mock_reader_instance = MagicMock()
    mock_reader_instance.open.side_effect = Exception("Native Boom!")
    mock_reader_cls.return_value = mock_reader_instance

    # Run with native enabled (should fail and fallback)
    with patch('sysdiag_analyzer.modules.logs.HAS_NATIVE_JOURNAL', True), \
         patch('sysdiag_analyzer.modules.logs.HAS_CYSYSTEMD', True):
        result = logs.analyze_general_logs(min_priority=4)

    assert result.analysis_error is not None # Error should be set
    assert "Native journal access failed" in result.analysis_error
    assert "Native Boom!" in result.analysis_error
    assert result.log_source == "journalctl" # Should have fallen back
    # Results should match the fallback data
    assert result.total_entries_analyzed == len(MOCK_JOURNALCTL_JSON_OUTPUT_PRIO_4.strip().splitlines())
    assert_patterns_match(result.detected_patterns, EXPECTED_PATTERNS_PRIO_4)
    mock_reader_instance.open.assert_called_once()
    mock_run_subprocess_logs.assert_called_once() # Check fallback was called

# Scenario 4: Fallback Command Error
@patch('sysdiag_analyzer.modules.logs.HAS_NATIVE_JOURNAL', False)
def test_analyze_logs_fallback_cmd_error(mock_run_subprocess_logs):
    # Use boot_offset=-99 to trigger failure in mock side_effect
    result = logs.analyze_general_logs(boot_offset=-99)

    assert result.analysis_error is not None
    assert "journalctl command failed" in result.analysis_error
    assert "journalctl command failed test" in result.analysis_error
    assert result.log_source == "journalctl"
    assert result.total_entries_analyzed == 0
    assert len(result.detected_patterns) == 0
    mock_run_subprocess_logs.assert_called_once()

# Scenario 5: Fallback JSON Parsing Error
@patch('sysdiag_analyzer.modules.logs.HAS_NATIVE_JOURNAL', False)
def test_analyze_logs_fallback_json_error(mock_run_subprocess_logs, caplog):
    # Use boot_offset=-98 to trigger invalid JSON in mock side_effect
    result = logs.analyze_general_logs(boot_offset=-98)

    assert result.analysis_error is not None # Error should be set now
    # FIX: Check for the summary error message added after the loop
    assert "Errors occurred while parsing journalctl JSON output" in result.analysis_error
    assert "Skipping invalid JSON line" in caplog.text # Check log message
    assert result.log_source == "journalctl"
    # Might have partial counts depending on where error occurred
    # Check that analysis error is set
    mock_run_subprocess_logs.assert_called_once()

# Scenario 6: No Issues Found
@patch('sysdiag_analyzer.modules.logs.HAS_NATIVE_JOURNAL', False)
def test_analyze_logs_no_issues(mock_run_subprocess_logs):
    # Use boot_offset=-97 to trigger no-issues data in mock side_effect
    result = logs.analyze_general_logs(boot_offset=-97)

    assert result.analysis_error is None
    assert result.log_source == "journalctl"
    assert result.total_entries_analyzed == len(MOCK_JOURNALCTL_JSON_OUTPUT_NO_ISSUES.strip().splitlines())
    assert len(result.detected_patterns) == 0
    mock_run_subprocess_logs.assert_called_once()

# Scenario 7: Pattern Matching Accuracy (Example: OOM)
@patch('sysdiag_analyzer.modules.logs.HAS_NATIVE_JOURNAL', False)
def test_analyze_logs_pattern_oom(mock_run_subprocess_logs):
    oom_line = json.dumps({"PRIORITY": "3", "MESSAGE": "Memory cgroup out of memory: Killed process 1234 (java)", "_SYSTEMD_UNIT": "kernel", "_PID": "0", "__REALTIME_TIMESTAMP": f"{T_USEC_1}"})
    mock_run_subprocess_logs.side_effect = [(True, oom_line, "")]

    result = logs.analyze_general_logs(min_priority=4)

    assert result.analysis_error is None
    assert len(result.detected_patterns) == 1
    oom_pattern = result.detected_patterns[0]
    assert oom_pattern.pattern_type == "OOM"
    assert oom_pattern.pattern_key == "oom-killer"
    assert oom_pattern.count == 1
    assert oom_pattern.level == "ERR"
    assert "Killed process 1234 (java)" in oom_pattern.example_messages[0]

# Scenario 8: Boot Offset and Priority Filtering (Fallback Focus)
@patch('sysdiag_analyzer.modules.logs.HAS_NATIVE_JOURNAL', False)
def test_analyze_logs_options_fallback(mock_run_subprocess_logs):
    # Test different boot offset
    logs.analyze_general_logs(boot_offset=-1, min_priority=3)
    call_args_list = mock_run_subprocess_logs.call_args_list
    assert len(call_args_list) == 1
    cmd_args = call_args_list[0].args[0]
    assert "-b-1" in cmd_args
    assert "-p3..0" in cmd_args

    # Test different priority
    mock_run_subprocess_logs.reset_mock()
    logs.analyze_general_logs(boot_offset=0, min_priority=5)
    call_args_list = mock_run_subprocess_logs.call_args_list
    assert len(call_args_list) == 1
    cmd_args = call_args_list[0].args[0]
    assert "-b0" in cmd_args
    assert "-p5..0" in cmd_args
