# tests/test_main.py
# -*- coding: utf-8 -*-

import pytest
import re # Import re for ANSI stripping
from unittest.mock import patch, MagicMock, ANY, mock_open
from typer.testing import CliRunner
from pathlib import Path # Import Path
import datetime # Import datetime
import time # Import time
import os # Import os
from dataclasses import asdict # Import asdict

# Module to test (main application entry point)
from sysdiag_analyzer.main import app
from sysdiag_analyzer.datatypes import (
    SystemReport, UnitHealthInfo # Add UnitHealthInfo
)

# Conditional import for ML tests
try:
    from sysdiag_analyzer import ml_engine
    import pandas as pd
    HAS_ML_LIBS_FOR_TEST = ml_engine.HAS_ML_LIBS
except ImportError:
    HAS_ML_LIBS_FOR_TEST = False
    pd = None

# Conditional import for LLM tests
try:
    from sysdiag_analyzer import llm_analyzer
    HAS_LLM_ENGINE_FOR_TEST = True
    HAS_LLM_OLLAMA_FOR_TEST = llm_analyzer.HAS_OLLAMA
except ImportError:
    HAS_LLM_ENGINE_FOR_TEST = False
    HAS_LLM_OLLAMA_FOR_TEST = False
    llm_analyzer = None

# --- Helper Function ---
ANSI_ESCAPE_PATTERN = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def strip_ansi(text: str) -> str:
    """Removes ANSI escape sequences from a string."""
    return ANSI_ESCAPE_PATTERN.sub('', text)

# --- Fixtures ---
@pytest.fixture(scope="module")
def runner():
    return CliRunner()

@pytest.fixture
def mock_default_config(tmp_path): # Add tmp_path fixture
    """Provides a default config dictionary for mocking load_config."""
    # Use tmp_path for directories to ensure write permissions
    history_dir = tmp_path / "history"
    model_dir = tmp_path / "models"
    return {
        "llm": {"provider": "ollama", "model": "default_test_model", "host": None},
        "history": {"directory": str(history_dir), "max_files": 50},
        "models": {"directory": str(model_dir), "anomaly_contamination": "auto", "min_samples_train": 10},
    }

@pytest.fixture
def mock_unit_list():
    """Provides a mock list of UnitHealthInfo objects."""
    return [UnitHealthInfo(name="unit1.service", path="/fake/path1"), UnitHealthInfo(name="unit2.target")]

# --- Tests for `run` command flags ---

# Patch the actual function called by the CLI command
@patch('sysdiag_analyzer.main.run_full_analysis')
# Patch the unit fetching helpers called *within* run_full_analysis in main.py
@patch('sysdiag_analyzer.main._get_all_units_dbus')
@patch('sysdiag_analyzer.main._get_all_units_json')
@patch('sysdiag_analyzer.main._get_systemd_manager_interface') # Mock DBus connection attempt
@patch('sysdiag_analyzer.main.load_config') # Mock load_config
def test_run_command_flags(
    mock_load_config, mock_get_manager, mock_get_units_json, mock_get_units_dbus,
    mock_run_full, runner, mock_default_config, mock_unit_list
):
    """Test calling run with various flags and config loading."""
    mock_load_config.return_value = mock_default_config
    mock_get_manager.return_value = MagicMock() # Simulate successful DBus connection
    mock_get_units_dbus.return_value = (mock_unit_list, None)
    mock_get_units_json.return_value = ([], "Fallback not needed") # Ensure fallback isn't used here
    mock_run_full.return_value = SystemReport()

    # Test default run
    result = runner.invoke(app, ["run"])
    assert result.exit_code == 0
    mock_load_config.assert_called_with(config_path_override=None)
    mock_get_manager.assert_called_once()
    mock_get_units_dbus.assert_called_once()
    mock_get_units_json.assert_not_called()
    mock_run_full.assert_called_with(
        history_dir=Path(mock_default_config["history"]["directory"]),
        model_dir=Path(mock_default_config["models"]["directory"]),
        all_units=mock_unit_list,      # Added
        dbus_manager=ANY,              # Added (use ANY or mock_get_manager.return_value)
        since=None, enable_ebpf=False, analyze_full_graph=False, analyze_ml=False,
        analyze_llm=False, llm_config=None
    )
    # Reset mocks for next call
    mock_load_config.reset_mock()
    mock_get_manager.reset_mock()
    mock_get_units_dbus.reset_mock()
    mock_get_units_json.reset_mock()
    mock_run_full.reset_mock()
    # Re-set return value for next test section if needed
    mock_get_units_dbus.return_value = (mock_unit_list, None)


    # Test --config flag
    result = runner.invoke(app, ["run", "--config", "/custom/path.toml"])
    assert result.exit_code == 0
    mock_load_config.assert_called_with(config_path_override=Path("/custom/path.toml"))
    mock_get_units_dbus.assert_called_once()
    mock_run_full.assert_called_with(
        history_dir=Path(mock_default_config["history"]["directory"]),
        model_dir=Path(mock_default_config["models"]["directory"]),
        all_units=mock_unit_list,      # Added
        dbus_manager=ANY,              # Added
        since=None, enable_ebpf=False, analyze_full_graph=False, analyze_ml=False,
        analyze_llm=False, llm_config=None
    )
    # Reset mocks
    mock_load_config.reset_mock()
    mock_get_manager.reset_mock()
    mock_get_units_dbus.reset_mock()
    mock_get_units_json.reset_mock()
    mock_run_full.reset_mock()
    # Re-set return value for next test section if needed
    mock_get_units_dbus.return_value = (mock_unit_list, None)


    # Test --analyze-llm (requires valid config from mock)
    llm_config = {"provider": "ollama", "model": "test-model"}
    mock_load_config.return_value = {
        **mock_default_config,
        "llm": llm_config
    }
    with patch('sysdiag_analyzer.main.HAS_LLM_ENGINE', True), \
         patch('sysdiag_analyzer.main.HAS_LLM_OLLAMA', True):
        result = runner.invoke(app, ["run", "--analyze-llm"])

    assert result.exit_code == 0
    mock_load_config.assert_called_with(config_path_override=None)
    mock_get_units_dbus.assert_called_once()
    mock_run_full.assert_called_with(
        history_dir=Path(mock_default_config["history"]["directory"]),
        model_dir=Path(mock_default_config["models"]["directory"]),
        all_units=mock_unit_list,      # Added
        dbus_manager=ANY,              # Added
        since=None, enable_ebpf=False, analyze_full_graph=False, analyze_ml=False,
        analyze_llm=True, llm_config=llm_config # Check LLM args passed
    )


# --- Test LLM Fail-Fast Validation ---
@patch('sysdiag_analyzer.main.run_full_analysis')
@patch('sysdiag_analyzer.main.load_config')
def test_run_llm_fail_fast_no_provider(mock_load_config, mock_run_full, runner, mock_default_config):
    # Provide a config missing the 'provider'
    config_no_provider = mock_default_config.copy()
    config_no_provider['llm'] = {"model": "some-model"} # Missing provider
    mock_load_config.return_value = config_no_provider

    with patch('sysdiag_analyzer.main.HAS_LLM_ENGINE', True):
        result = runner.invoke(app, ["run", "--analyze-llm"])

    assert result.exit_code == 1
    output_clean = strip_ansi(result.output)
    assert "'provider' is not specified in the [llm]" in output_clean
    mock_run_full.assert_not_called()

@patch('sysdiag_analyzer.main.run_full_analysis')
@patch('sysdiag_analyzer.main.load_config')
def test_run_llm_fail_fast_no_model(mock_load_config, mock_run_full, runner, mock_default_config):
    # Provide a config missing the 'model'
    config_no_model = mock_default_config.copy()
    config_no_model['llm'] = {"provider": "ollama"} # Missing model
    mock_load_config.return_value = config_no_model

    with patch('sysdiag_analyzer.main.HAS_LLM_ENGINE', True), \
         patch('sysdiag_analyzer.main.HAS_LLM_OLLAMA', True):
        result = runner.invoke(app, ["run", "--analyze-llm"])

    assert result.exit_code == 1
    output_clean = strip_ansi(result.output)
    assert "'model' is not specified" in output_clean
    assert "in the [llm] section" in output_clean
    assert "--llm-model" in output_clean
    mock_run_full.assert_not_called()

# --- Test Persistence Logic (_save_report, _apply_retention) ---
@pytest.fixture
def temp_dir_path(tmp_path):
    return tmp_path

def test_save_report_success(temp_dir_path):
    # (Test logic remains the same)
    mock_report = SystemReport(hostname="test-host", boot_id="test-boot-id", errors=[])
    history_dir = temp_dir_path / "history"
    from sysdiag_analyzer.main import _save_report
    with patch('sysdiag_analyzer.main.get_boot_id', return_value="test-boot-id"), \
         patch('sysdiag_analyzer.main.datetime') as mock_datetime, \
         patch('sysdiag_analyzer.main.gzip.open', mock_open()) as mock_gz_open, \
         patch('sysdiag_analyzer.main.json.dumps', return_value='{"report": "data"}') as mock_json_dumps:
        mock_now = datetime.datetime(2025, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        mock_datetime.datetime.now.return_value = mock_now
        _save_report(mock_report, history_dir)
    assert history_dir.exists()
    expected_filename = history_dir / "report-test-boot-id-20250101T120000Z.jsonl.gz"
    mock_gz_open.assert_called_once_with(expected_filename, "wt", encoding="utf-8")
    mock_json_dumps.assert_called_once_with(asdict(mock_report), default=str)
    handle = mock_gz_open()
    handle.write.assert_called_once_with('{"report": "data"}\n')
    assert not mock_report.errors

def test_apply_retention_delete_old(temp_dir_path):
    # (Test logic remains the same)
    history_dir = temp_dir_path / "history"
    history_dir.mkdir()
    mock_files = []
    mtimes = {}
    base_time = time.time()
    max_files = 5
    num_extra = 3
    num_total = max_files + num_extra
    for i in range(num_total):
        fpath = history_dir / f"report-{i}.jsonl.gz"
        fpath.touch()
        mtime = base_time - (num_total - i) * 3600
        os.utime(fpath, (mtime, mtime))
        mock_files.append(fpath)
        mtimes[fpath] = mtime
    from sysdiag_analyzer.main import _apply_retention
    _apply_retention(history_dir, max_files)
    remaining_files = sorted(list(history_dir.glob("*.gz")), key=os.path.getmtime)
    assert len(remaining_files) == max_files
    assert all(f not in remaining_files for f in mock_files[:num_extra])
    assert all(f in remaining_files for f in mock_files[num_extra:])


# --- Test `run` Command Integration (Save Flag) ---
@patch('sysdiag_analyzer.main.run_full_analysis')
@patch('sysdiag_analyzer.main._save_report')
@patch('sysdiag_analyzer.main._apply_retention')
@patch('sysdiag_analyzer.main._get_all_units_dbus') # Add mocks for unit fetching in main
@patch('sysdiag_analyzer.main._get_all_units_json')
@patch('sysdiag_analyzer.main._get_systemd_manager_interface')
@patch('sysdiag_analyzer.main.load_config')
def test_run_command_integration_save(
    mock_load_config, mock_get_manager, mock_get_units_json, mock_get_units_dbus,
    mock_apply_retention, mock_save_report, mock_run_full, runner, mock_default_config, mock_unit_list
):
    """Test run command saves report by default."""
    mock_load_config.return_value = mock_default_config
    mock_get_manager.return_value = MagicMock()
    mock_get_units_dbus.return_value = (mock_unit_list, None)
    mock_report = SystemReport(hostname="test")
    mock_run_full.return_value = mock_report

    result = runner.invoke(app, ["run"])

    assert result.exit_code == 0
    mock_get_units_dbus.assert_called_once()
    mock_run_full.assert_called_once_with(
        history_dir=Path(mock_default_config["history"]["directory"]),
        model_dir=Path(mock_default_config["models"]["directory"]),
        all_units=mock_unit_list,
        dbus_manager=ANY,
        since=None, enable_ebpf=False, analyze_full_graph=False, analyze_ml=False,
        analyze_llm=False, llm_config=None
    )
    mock_save_report.assert_called_once_with(mock_report, Path(mock_default_config["history"]["directory"]))
    mock_apply_retention.assert_called_once_with(Path(mock_default_config["history"]["directory"]), mock_default_config["history"]["max_files"])

@patch('sysdiag_analyzer.main.run_full_analysis')
@patch('sysdiag_analyzer.main._save_report')
@patch('sysdiag_analyzer.main._apply_retention')
@patch('sysdiag_analyzer.main._get_all_units_dbus')
@patch('sysdiag_analyzer.main._get_all_units_json')
@patch('sysdiag_analyzer.main._get_systemd_manager_interface')
@patch('sysdiag_analyzer.main.load_config')
def test_run_command_integration_no_save(
    mock_load_config, mock_get_manager, mock_get_units_json, mock_get_units_dbus,
    mock_apply_retention, mock_save_report, mock_run_full, runner, mock_default_config, mock_unit_list
):
    """Test --no-save flag prevents saving."""
    mock_load_config.return_value = mock_default_config
    mock_get_manager.return_value = MagicMock()
    mock_get_units_dbus.return_value = (mock_unit_list, None)
    mock_report = SystemReport(hostname="test")
    mock_run_full.return_value = mock_report

    result = runner.invoke(app, ["run", "--no-save"])

    assert result.exit_code == 0
    mock_get_units_dbus.assert_called_once()
    mock_run_full.assert_called_once() # Analysis still run
    mock_save_report.assert_not_called() # Not saved
    mock_apply_retention.assert_not_called() # Retention not applied

@pytest.fixture
def mock_history_dir_show(tmp_path):
    """Creates mock history directory and files with deterministic modification times."""
    hist_dir = tmp_path / "show_hist"
    hist_dir.mkdir()

    # Define files and their corresponding timestamps to guarantee sorting order
    files_to_create = {
        "report-boot1-20250102T100000Z.jsonl.gz": datetime.datetime(2025, 1, 2, 10, 0, 0, tzinfo=datetime.timezone.utc), # Newest
        "report-boot1-20250102T090000Z.jsonl.gz": datetime.datetime(2025, 1, 2, 9, 0, 0, tzinfo=datetime.timezone.utc),  # Second newest
        "report-boot0-20250101T120000Z.jsonl.gz": datetime.datetime(2025, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc), # Third newest
        "report-oldest-to-be-excluded.jsonl.gz": datetime.datetime(2025, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)   # Oldest
    }

    for filename, dt in files_to_create.items():
        file_path = hist_dir / filename
        file_path.touch()
        # Set the modification time to the exact, deterministic timestamp from the filename
        mtime = dt.timestamp()
        os.utime(file_path, (mtime, mtime))

    yield hist_dir


@patch('sysdiag_analyzer.main.load_config')
def test_show_history_success_rich(mock_load_config, mock_history_dir_show, runner):
    """Test the show-history command with a limit, checking for correct sorting and exclusion."""
    mock_load_config.return_value = {"history": {"directory": str(mock_history_dir_show)}}
    result = runner.invoke(app, ["show-history", "-n", "3"])

    assert result.exit_code == 0
    output = result.stdout
    print(output)
    # Check that the title and the three newest files are present
    assert "Recent Analysis Reports (Last 3)" in output
    assert "report-boot1-20250102T100000Z.jsonl.gz" in output
    assert "report-boot1-20250102T090000Z.jsonl.gz" in output
    assert "report-boot0-20250101T120000Z.jsonl.gz" in output

    # Crucially, check that the oldest file was excluded by the limit
    assert "report-oldest-to-be-excluded.jsonl.gz" not in output

    mock_load_config.assert_called_once_with(config_path_override=None)

pytestmark_ml = pytest.mark.skipif(not HAS_ML_LIBS_FOR_TEST, reason="Requires ML libraries")
@pytestmark_ml
@patch('sysdiag_analyzer.main.ml_engine.load_and_prepare_data')
@patch('sysdiag_analyzer.main.ml_engine.engineer_features')
@patch('sysdiag_analyzer.main.ml_engine.train_anomaly_models')
@patch('sysdiag_analyzer.main.check_privileges')
@patch('sysdiag_analyzer.main.load_config')
@patch('pathlib.Path.mkdir')
@patch('pathlib.Path.exists')
def test_retrain_ml_success(mock_exists, mock_mkdir, mock_load_config, mock_check_priv, mock_train, mock_engineer, mock_load_prep, runner, mock_default_config):
    mock_load_config.return_value = mock_default_config
    model_path = Path(mock_default_config["models"]["directory"])
    history_path = Path(mock_default_config["history"]["directory"])
    mock_exists.return_value = True
    if pd:
        mock_df = pd.DataFrame([{"unit_name": "unitA", "cpu": 100}])
    else:
        mock_df = MagicMock()
    mock_load_prep.return_value = mock_df
    mock_engineer.return_value = mock_df
    mock_train.return_value = ({"unitA": MagicMock()}, {"unitA": MagicMock()}, [])
    result = runner.invoke(app, ["retrain-ml", "-n", "30"])
    assert result.exit_code == 0
    mock_check_priv.assert_called_once()
    mock_load_config.assert_called_once_with(config_path_override=None)
    mock_load_prep.assert_called_once_with(history_dir=history_path, num_reports=30)
    mock_engineer.assert_called_once_with(mock_df)
    mock_train.assert_called_once_with(mock_df, model_path)
    assert "Successfully trained and saved" in result.stdout
