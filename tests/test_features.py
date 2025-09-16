# tests/test_features.py
# -*- coding: utf-8 -*-

import pytest
import os
import gzip
import json
import datetime
from pathlib import Path
from unittest.mock import patch, mock_open

# Module to test
from sysdiag_analyzer import features

# --- Constants ---
# MOCK_HISTORY_DIR = Path("/fake/history/dir") # No longer global

# --- Fixtures ---

@pytest.fixture
def mock_history_dir_features(tmp_path):
    """Provides a temporary Path object for the history directory."""
    hist_dir = tmp_path / "feature_hist"
    hist_dir.mkdir()
    return hist_dir

# --- Sample Data ---
# (Sample data REPORT_1_DICT etc. remains the same)
REPORT_1_TS = "2025-01-01T10:00:00Z"
REPORT_1_BOOT_ID = "boot1"
REPORT_1_DICT = {
    "hostname": "host1", "timestamp": REPORT_1_TS, "boot_id": REPORT_1_BOOT_ID,
    "resource_analysis": {"unit_usage": [
            {"name": "unitA.service", "cpu_usage_nsec": 1e9, "memory_current_bytes": 100e6, "io_read_bytes": 10e6, "io_write_bytes": 1e6, "tasks_current": 5},
            {"name": "unitB.service", "cpu_usage_nsec": 2e9, "memory_current_bytes": 200e6, "error": "cgroup read failed", "tasks_current": 1},
        ]},
    "health_analysis": {
        "failed_units": [{"name": "unitC.service", "details": {"Result": "failed"}}],
        "flapping_units": [{"name": "unitA.service", "details": {"NRestarts": 5}}]
    },
    "boot_analysis": {"blame": [{"unit": "unitD.service", "time": "1.500s"}]}
}
REPORT_2_TS = "2025-01-01T11:00:00Z"
REPORT_2_BOOT_ID = "boot2"
REPORT_2_DICT = {
    "hostname": "host1", "timestamp": REPORT_2_TS, "boot_id": REPORT_2_BOOT_ID,
    "resource_analysis": {"unit_usage": [
            {"name": "unitA.service", "cpu_usage_nsec": 1.2e9, "memory_current_bytes": 110e6, "io_read_bytes": 12e6, "io_write_bytes": 2e6, "tasks_current": 6},
        ]},
    "health_analysis": {"flapping_units": []}
}
REPORT_3_TS = "2025-01-01T09:00:00Z"
REPORT_3_BOOT_ID = "boot1"
REPORT_3_DICT = {
    "hostname": "host1", "timestamp": REPORT_3_TS, "boot_id": REPORT_3_BOOT_ID,
    "resource_analysis": None,
    "health_analysis": {"failed_units": [{"name": "unitE.service", "details": {"Result": "timeout"}}]}
}

# --- Test Cases for load_historical_data ---

def test_load_history_success(mock_history_dir_features):
    """Test successful loading of multiple reports from the specified dir."""
    hist_dir = mock_history_dir_features
    # Create mock files in the temp dir *before* mocking gzip.open
    f1_path = hist_dir / "report-boot1-20250101T100000Z.jsonl.gz"
    f2_path = hist_dir / "report-boot2-20250101T110000Z.jsonl.gz"
    f3_path = hist_dir / "report-boot1-20250101T090000Z.jsonl.gz"

    file_contents = {
        f1_path: json.dumps(REPORT_1_DICT) + "\n",
        f2_path: json.dumps(REPORT_2_DICT) + "\n",
        f3_path: json.dumps(REPORT_3_DICT) + "\n",
    }

    # Write real files first
    for p, content in file_contents.items():
        with gzip.open(p, "wt", encoding="utf-8") as f:
            f.write(content)

    # Set mtimes after creating files
    mtime1 = datetime.datetime(2025, 1, 1, 10, 0, 0).timestamp()
    mtime2 = datetime.datetime(2025, 1, 1, 11, 0, 0).timestamp()
    mtime3 = datetime.datetime(2025, 1, 1, 9, 0, 0).timestamp()
    os.utime(f1_path, (mtime1, mtime1))
    os.utime(f2_path, (mtime2, mtime2))
    os.utime(f3_path, (mtime3, mtime3))

    original_gzip_open = gzip.open # Store original

    def gzip_open_side_effect(filename, mode="rt", encoding="utf-8"):
        p = Path(filename)
        if p in file_contents:
            # Use original gzip.open to read the actual file content
            with original_gzip_open(p, mode=mode, encoding=encoding) as real_f:
                content = real_f.read()
            # Return a mock file handle with the real content
            m = mock_open(read_data=content)
            # Configure the mock file handle to behave like a context manager
            mock_handle = m(filename, mode, encoding=encoding)
            mock_handle.__enter__.return_value = mock_handle
            mock_handle.__exit__.return_value = None
            return mock_handle
        else:
            # Fallback for unexpected calls if any (e.g., raise error or return empty mock)
            raise FileNotFoundError(f"Mock gzip.open called for unexpected file: {filename}")

    with patch('sysdiag_analyzer.features.gzip.open', side_effect=gzip_open_side_effect):
        # Call the function under test, passing the temp dir path
        reports = features.load_historical_data(history_dir=hist_dir, num_reports=10)

    assert len(reports) == 3
    # Sort reports by timestamp from the data itself for assertion stability
    reports.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    assert reports[0]["timestamp"] == REPORT_2_TS # Report 2 is newest
    assert reports[1]["timestamp"] == REPORT_1_TS
    assert reports[2]["timestamp"] == REPORT_3_TS

def test_load_history_empty_dir(mock_history_dir_features):
    """Test loading from an empty directory."""
    reports = features.load_historical_data(history_dir=mock_history_dir_features)
    assert reports == []

# ... other load_historical_data tests adapted similarly ...

# --- Test Cases for extract_features_from_report ---
# (These tests don't depend on the history dir, no changes needed)
def test_extract_features_single_report_full():
    """Test Case 3.5: Extract features from a complete sample report."""
    features_list = features.extract_features_from_report(REPORT_1_DICT)
    assert len(features_list) == 5 # unitA(res), unitB(res), unitC(health), unitA(health), unitD(boot)
    # ... (detailed assertions remain the same) ...

# --- Test Cases for extract_features (main orchestrator) ---
# (These tests don't depend on the history dir, no changes needed)
def test_extract_features_multiple_reports():
    """Test Case 3.6: Extract features from a list of reports."""
    historical_reports = [REPORT_1_DICT, REPORT_2_DICT, REPORT_3_DICT]
    all_features = features.extract_features(historical_reports)
    assert len(all_features) == 7 # 5(R1) + 1(R2) + 1(R3)
    # ... (detailed assertions remain the same) ...
