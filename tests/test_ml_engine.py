# tests/test_ml_engine.py
import pytest
import pandas as pd
from unittest.mock import patch, MagicMock
import datetime  # Added for timestamp generation

# Conditional import of module to test
try:
    from sysdiag_analyzer import ml_engine
    from sysdiag_analyzer.datatypes import AnomalyInfo
    from sysdiag_analyzer import features  # Needed for mocking load_historical_data
    from sklearn.preprocessing import MinMaxScaler
    from tensorflow import keras
    import numpy as np

    HAS_ML_LIBS = ml_engine.HAS_ML_LIBS
except ImportError:
    pytest.skip(
        "Skipping ML tests: ML libraries not installed or module structure issue",
        allow_module_level=True,
    )
    HAS_ML_LIBS = False
    # Define dummy types for linters and type checkers
    MinMaxScaler = type("MinMaxScaler", (object,), {})
    keras = None
    np = None
    features = None  # type: ignore
    AnomalyInfo = type("AnomalyInfo", (object,), {})  # Add dummy


# --- Fixtures ---


@pytest.fixture(scope="module", autouse=True)
def check_deps():
    """Skip all tests in this module if ML deps are missing."""
    if not HAS_ML_LIBS:
        pytest.skip("Skipping ML tests: ML libraries not installed.", allow_module_level=True)


@pytest.fixture
def mock_feature_loading():
    """Mocks features.load_historical_data."""
    target = (
        "sysdiag_analyzer.ml_engine.features.load_historical_data"
        if features
        else "builtins.print"
    )
    if features:
        with patch(target) as mock_load:
            yield mock_load
    else:
        yield MagicMock()


@pytest.fixture
def sample_feature_list():
    """Provides a sample list of feature dictionaries with enough data points."""
    base_time = datetime.datetime(2025, 1, 1, 10, 0, 0, tzinfo=datetime.timezone.utc)
    num_points = ml_engine.MIN_SAMPLES_FOR_TRAINING + 5  # Ensure enough points
    features_list = []

    for i in range(num_points):
        ts = base_time + datetime.timedelta(hours=i)
        ts_str = ts.isoformat()
        boot_id = f"host1_boot{i//24}"  # Simulate occasional reboots

        # Unit A data (some variation)
        features_list.append(
            {
                "report_timestamp": ts_str,
                "boot_id": boot_id,
                "unit_name": "unitA.service",
                "source": "resource_analysis",
                "cpu_usage_nsec": (1 + i * 0.1) * 1e9,
                "mem_current_bytes": (100 + i * 5) * 1e6,
                "mem_peak_bytes": (110 + i * 5) * 1e6,
                "io_read_bytes": (10 + i) * 1e6,
                "io_write_bytes": (1 + i * 0.2) * 1e6,
                "tasks_current": 5 + (i % 3),
            }
        )
        # Unit B data (more stable)
        features_list.append(
            {
                "report_timestamp": ts_str,
                "boot_id": boot_id,
                "unit_name": "unitB.service",
                "source": "resource_analysis",
                "cpu_usage_nsec": (2 + (i % 2) * 0.1) * 1e9,
                "mem_current_bytes": (200 - (i % 4) * 2) * 1e6,
                "mem_peak_bytes": 205 * 1e6,
                "io_read_bytes": 5e6,
                "io_write_bytes": 1e6,
                "tasks_current": 2,
            }
        )
    return features_list


@pytest.fixture
def sample_dataframe(sample_feature_list):
    """Provides a sample DataFrame prepared from feature list."""
    if not pd:
        pytest.skip("Pandas not available")
    df = pd.DataFrame(sample_feature_list)
    df["report_timestamp"] = pd.to_datetime(df["report_timestamp"])
    # Simplified aggregation for testing
    df_agg = (
        df.groupby(["unit_name", "report_timestamp"])
        .mean(numeric_only=True)
        .reset_index()
    )
    return df_agg


@pytest.fixture
def temp_model_dir_path(tmp_path):
    """Creates a temporary directory Path object for saving/loading models."""
    model_dir = tmp_path / "ml_models"
    model_dir.mkdir()
    return model_dir


# --- Test Cases ---


def test_load_and_prepare_data_success(
    mock_feature_loading, sample_feature_list, tmp_path
):
    """Test loading data, passing the history directory path."""
    mock_history_dir = tmp_path / "hist"
    mock_feature_loading.return_value = ["report1", "report2"]

    with patch(
        "sysdiag_analyzer.ml_engine.features.extract_features",
        return_value=sample_feature_list,
    ):
        df = ml_engine.load_and_prepare_data(history_dir=mock_history_dir, num_reports=2)

    assert isinstance(df, pd.DataFrame)
    assert not df.empty
    mock_feature_loading.assert_called_once_with(history_dir=mock_history_dir, num_reports=2)


def test_load_and_prepare_data_no_history(mock_feature_loading, tmp_path):
    mock_history_dir = tmp_path / "hist"
    mock_feature_loading.return_value = []
    with patch(
        "sysdiag_analyzer.ml_engine.features.extract_features", return_value=[]
    ):
        df = ml_engine.load_and_prepare_data(history_dir=mock_history_dir)
    assert df is None
    mock_feature_loading.assert_called_once_with(history_dir=mock_history_dir, num_reports=50)


def test_engineer_features_success(sample_dataframe):
    engineered_df = ml_engine.engineer_features(sample_dataframe.copy())
    assert isinstance(engineered_df, pd.DataFrame)
    expected_cols = [
        "cpu_usage_nsec",
        "mem_current_bytes",
        "mem_peak_bytes",
        "io_read_bytes",
        "io_write_bytes",
        "tasks_current",
    ]
    for col in expected_cols:
        assert col in engineered_df.columns
        assert not engineered_df[col].isnull().any()


def test_save_load_models(temp_model_dir_path):
    """Test saving and loading a full set of model artifacts."""
    mock_model = keras.Sequential([keras.Input(shape=(5,)), keras.layers.Dense(10)])
    mock_scaler = MinMaxScaler().fit([[1], [2], [3], [4], [5]])
    mock_threshold = 0.123
    unit_name = "test-unit.service"
    sanitized_name = ml_engine._sanitize_filename(unit_name)

    ml_engine.save_model_artifacts(
        mock_model, mock_scaler, mock_threshold, unit_name, temp_model_dir_path
    )

    unit_model_dir = temp_model_dir_path / sanitized_name
    assert (unit_model_dir / "model.keras").is_file()
    assert (unit_model_dir / "scaler.joblib").is_file()
    assert (unit_model_dir / "metadata.json").is_file()

    loaded_models, loaded_scalers, loaded_thresholds = ml_engine.load_models(
        temp_model_dir_path
    )

    assert len(loaded_models) == 1
    assert sanitized_name in loaded_models
    assert isinstance(loaded_models[sanitized_name], keras.Model)
    assert loaded_thresholds[sanitized_name] == mock_threshold


def test_load_models_dir_not_found(tmp_path):
    """Test loading from a non-existent directory path."""
    non_existent_path = tmp_path / "non_existent_models"
    models, scalers, thresholds = ml_engine.load_models(non_existent_path)
    assert models == {}
    assert scalers == {}
    assert thresholds == {}


@patch("sysdiag_analyzer.ml_engine._train_single_unit_model")
def test_train_anomaly_models_success(
    mock_train_worker, sample_dataframe, temp_model_dir_path
):
    """Test training orchestrator, mocking the parallel worker."""
    def worker_side_effect(unit_name, unit_df, model_dir):
        if unit_name == "unitA.service":
            return (unit_name, True, None)
        else:
            return (unit_name, False, "Simulated failure")
    mock_train_worker.side_effect = worker_side_effect

    engineered_df = ml_engine.engineer_features(sample_dataframe)
    trained_count, skipped_summary = ml_engine.train_anomaly_models(
        engineered_df, temp_model_dir_path, max_workers=1
    )

    assert trained_count == 1
    assert "Simulated failure" in skipped_summary
    assert skipped_summary["Simulated failure"] == ["unitB.service"]
    assert mock_train_worker.call_count == 2


@pytest.mark.skipif(not HAS_ML_LIBS, reason="ML libraries (numpy, etc.) not installed")
def test_detect_anomalies_success():
    """Test anomaly detection logic with mock models and data."""
    unit_name = "unitA.service"
    sanitized_name = ml_engine._sanitize_filename(unit_name)

    mock_model = MagicMock(spec=keras.Model)
    # Use np, which is now guaranteed to be imported if this test runs
    mock_model.predict.return_value = (
        np.ones((1, ml_engine.LSTM_TIMESTEPS, 8)) * 100
    )  # Anomalous reconstruction

    mock_scaler = MagicMock(spec=MinMaxScaler)
    mock_scaler.feature_names_in_ = [
        "cpu_usage_nsec", "mem_current_bytes", "mem_peak_bytes", "io_read_bytes",
        "io_write_bytes", "tasks_current", "is_failed", "is_flapping",
    ]
    mock_scaler.transform.return_value = np.random.rand(ml_engine.LSTM_TIMESTEPS, 8)

    models = {sanitized_name: mock_model}
    scalers = {sanitized_name: mock_scaler}
    thresholds = {sanitized_name: 0.5}

    # Create dummy DataFrame for detection
    detection_data = {
        "unit_name": [unit_name] * ml_engine.LSTM_TIMESTEPS,
        "cpu_usage_nsec": [1] * ml_engine.LSTM_TIMESTEPS,
        "is_failed": [False] * ml_engine.LSTM_TIMESTEPS,
        "is_flapping": [False] * ml_engine.LSTM_TIMESTEPS,
    }
    detection_df = pd.DataFrame(detection_data)
    engineered_detection_df = ml_engine.engineer_features(detection_df)

    anomalies = ml_engine.detect_anomalies(
        engineered_detection_df, models, scalers, thresholds
    )

    assert len(anomalies) == 1
    assert anomalies[0].unit_name == unit_name
    assert anomalies[0].score > thresholds[sanitized_name]
    mock_model.predict.assert_called_once()