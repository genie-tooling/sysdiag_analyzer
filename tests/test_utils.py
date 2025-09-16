# tests/test_utils.py
# -*- coding: utf-8 -*-

import pytest
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

# Module to test
from sysdiag_analyzer import utils

# --- Fixtures ---

@pytest.fixture(autouse=True)
def clear_boot_id_cache():
    """Fixture to automatically clear the boot ID cache before each test."""
    utils._cached_boot_id = None
    yield
    utils._cached_boot_id = None

@pytest.fixture
def mock_run_subprocess_util():
    """Mocks utils.run_subprocess."""
    with patch('sysdiag_analyzer.utils.run_subprocess') as mock_run:
        yield mock_run

@pytest.fixture
def mock_proc_boot_id_path():
    """Mocks pathlib.Path for /proc/sys/kernel/random/boot_id."""
    mock_path = MagicMock(spec=Path)
    mock_path.is_file.return_value = True
    mock_path.read_text.return_value = "proc-boot-id-1234567890abcdef\n" # Example content
    with patch('sysdiag_analyzer.utils.Path') as mock_path_cls:
        # Make Path('/proc/...') return our specific mock
        def path_side_effect(p):
            if str(p) == "/proc/sys/kernel/random/boot_id":
                return mock_path
            # Return a default MagicMock for other paths if needed
            return MagicMock(spec=Path)
        mock_path_cls.side_effect = path_side_effect
        yield mock_path # Yield the specific mock for assertions

# --- Test Cases for get_boot_id ---

def test_get_boot_id_success_journalctl(mock_run_subprocess_util, mock_proc_boot_id_path):
    """Test Case 1.1: Success via journalctl."""
    mock_boot_id = "journal-boot-id-abcdef1234567890"
    # Simulate journalctl output which is JSON *lines*
    mock_json_output = json.dumps({"some_other_key": "value"}) + "\n" + json.dumps({"boot_id": mock_boot_id}) + "\n"
    mock_run_subprocess_util.return_value = (True, mock_json_output, "")

    # First call
    boot_id = utils.get_boot_id()
    assert boot_id == mock_boot_id
    mock_run_subprocess_util.assert_called_once_with(
        ["journalctl", "--list-boots", "-n", "1", "--no-pager", "--output=json"]
    )
    mock_proc_boot_id_path.is_file.assert_not_called() # Fallback should not be reached

    # Second call (cached)
    boot_id_cached = utils.get_boot_id()
    assert boot_id_cached == mock_boot_id
    # Assert mock was still only called once
    mock_run_subprocess_util.assert_called_once()

def test_get_boot_id_failure_journalctl_command(mock_run_subprocess_util, mock_proc_boot_id_path):
    """Test Case 1.2: journalctl command fails, fallback to /proc."""
    mock_run_subprocess_util.return_value = (False, "", "journalctl error")
    expected_proc_id = "procbootid1234567890abcdef" # Dashes removed

    boot_id = utils.get_boot_id()

    assert boot_id == expected_proc_id
    mock_run_subprocess_util.assert_called_once() # Journalctl was attempted
    mock_proc_boot_id_path.is_file.assert_called_once()
    mock_proc_boot_id_path.read_text.assert_called_once()

def test_get_boot_id_failure_journalctl_json_parse(mock_run_subprocess_util, mock_proc_boot_id_path, caplog):
    """Test Case 1.3: journalctl returns invalid JSON, fallback to /proc."""
    mock_run_subprocess_util.return_value = (True, "this is not json\n", "")
    expected_proc_id = "procbootid1234567890abcdef"

    boot_id = utils.get_boot_id()

    assert boot_id == expected_proc_id
    mock_run_subprocess_util.assert_called_once()
    mock_proc_boot_id_path.is_file.assert_called_once()
    mock_proc_boot_id_path.read_text.assert_called_once()
    assert "Failed to parse JSON line from journalctl --list-boots" in caplog.text

def test_get_boot_id_failure_journalctl_empty_or_no_id(mock_run_subprocess_util, mock_proc_boot_id_path):
    """Test Case 1.4: journalctl output empty or lacks boot_id, fallback to /proc."""
    # Test empty output
    mock_run_subprocess_util.return_value = (True, "", "")
    expected_proc_id = "procbootid1234567890abcdef"
    boot_id = utils.get_boot_id()
    assert boot_id == expected_proc_id
    mock_run_subprocess_util.assert_called_once()
    mock_proc_boot_id_path.is_file.assert_called_once()
    mock_proc_boot_id_path.read_text.assert_called_once()

    # Reset mocks and cache for next sub-test
    utils._cached_boot_id = None
    mock_run_subprocess_util.reset_mock()
    mock_proc_boot_id_path.reset_mock()
    mock_proc_boot_id_path.is_file.return_value = True # Ensure is_file is reset

    # Test JSON without boot_id
    mock_json_output = json.dumps({"some_other_key": "value"}) + "\n"
    mock_run_subprocess_util.return_value = (True, mock_json_output, "")
    boot_id = utils.get_boot_id()
    assert boot_id == expected_proc_id
    mock_run_subprocess_util.assert_called_once()
    mock_proc_boot_id_path.is_file.assert_called_once()
    mock_proc_boot_id_path.read_text.assert_called_once()

def test_get_boot_id_failure_journalctl_and_proc(mock_run_subprocess_util, mock_proc_boot_id_path, caplog):
    """Test Case 1.5: Both journalctl and /proc fail."""
    mock_run_subprocess_util.return_value = (False, "", "journalctl error")
    mock_proc_boot_id_path.read_text.side_effect = OSError("Cannot read /proc file")

    boot_id = utils.get_boot_id()

    assert boot_id is None
    mock_run_subprocess_util.assert_called_once()
    mock_proc_boot_id_path.is_file.assert_called_once()
    mock_proc_boot_id_path.read_text.assert_called_once()
    assert "Could not read boot ID from /proc/sys/kernel/random/boot_id" in caplog.text
    assert "Could not determine boot ID" in caplog.text

def test_get_boot_id_success_proc_only(mock_run_subprocess_util, mock_proc_boot_id_path):
    """Test Case 1.6: journalctl fails, /proc succeeds."""
    mock_run_subprocess_util.return_value = (False, "", "journalctl error")
    expected_proc_id = "procbootid1234567890abcdef"

    boot_id = utils.get_boot_id()

    assert boot_id == expected_proc_id
    mock_run_subprocess_util.assert_called_once()
    mock_proc_boot_id_path.is_file.assert_called_once()
    mock_proc_boot_id_path.read_text.assert_called_once()

def test_get_boot_id_caching(mock_run_subprocess_util, mock_proc_boot_id_path):
    """Test Case 1.7: Caching prevents multiple calls."""
    # Setup for journalctl success
    mock_boot_id = "journal-boot-id-abcdef1234567890"
    mock_json_output = json.dumps({"boot_id": mock_boot_id}) + "\n"
    mock_run_subprocess_util.return_value = (True, mock_json_output, "")

    # First call
    boot_id1 = utils.get_boot_id()
    assert boot_id1 == mock_boot_id
    assert mock_run_subprocess_util.call_count == 1
    assert mock_proc_boot_id_path.is_file.call_count == 0

    # Second call
    boot_id2 = utils.get_boot_id()
    assert boot_id2 == mock_boot_id
    # Assert mocks were not called again
    assert mock_run_subprocess_util.call_count == 1
    assert mock_proc_boot_id_path.is_file.call_count == 0

    # --- Test caching with /proc fallback ---
    utils._cached_boot_id = None # Clear cache
    mock_run_subprocess_util.reset_mock()
    mock_proc_boot_id_path.reset_mock()
    mock_proc_boot_id_path.is_file.return_value = True # Reset mock state

    # Setup for journalctl failure, /proc success
    mock_run_subprocess_util.return_value = (False, "", "journalctl error")
    expected_proc_id = "procbootid1234567890abcdef"

    # First call
    boot_id3 = utils.get_boot_id()
    assert boot_id3 == expected_proc_id
    assert mock_run_subprocess_util.call_count == 1
    assert mock_proc_boot_id_path.is_file.call_count == 1
    assert mock_proc_boot_id_path.read_text.call_count == 1

    # Second call
    boot_id4 = utils.get_boot_id()
    assert boot_id4 == expected_proc_id
    # Assert mocks were not called again
    assert mock_run_subprocess_util.call_count == 1
    assert mock_proc_boot_id_path.is_file.call_count == 1
    assert mock_proc_boot_id_path.read_text.call_count == 1
