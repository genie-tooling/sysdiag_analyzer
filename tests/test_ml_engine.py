# tests/test_ml_engine.py
import pytest
import pandas as pd
import numpy as np
import joblib
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock, call
import datetime # Added for timestamp generation

# Conditional import of module to test
try:
    from sysdiag_analyzer import ml_engine
    from sysdiag_analyzer.datatypes import AnomalyInfo
    from sysdiag_analyzer import features # Needed for mocking load_historical_data
    from sklearn.ensemble import IsolationForest
    # Phase 10 Fix 2: Use MinMaxScaler
    from sklearn.preprocessing import MinMaxScaler
    HAS_ML_LIBS = ml_engine.HAS_ML_LIBS
except ImportError:
    pytest.skip("Skipping ML tests: ML libraries not installed or module structure issue", allow_module_level=True)
    HAS_ML_LIBS = False
    IsolationForest = type('IsolationForest', (object,), {})
    # Use dummy scaler type
    MinMaxScaler = type('MinMaxScaler', (object,), {}) # Changed Scaler Type
    features = None # type: ignore
    AnomalyInfo = type('AnomalyInfo', (object,), {}) # Add dummy


# --- Fixtures ---

@pytest.fixture(scope="module", autouse=True)
def check_deps():
    """Skip all tests in this module if ML deps are missing."""
    if not HAS_ML_LIBS:
        pytest.skip("Skipping ML tests: ML libraries not installed.", allow_module_level=True)

@pytest.fixture
def mock_feature_loading():
    """Mocks features.load_historical_data."""
    # Make sure features module is mocked if it failed import earlier
    target = 'sysdiag_analyzer.ml_engine.features.load_historical_data' if features else 'builtins.print' # Dummy target if features is None
    if features:
        with patch(target) as mock_load:
            yield mock_load
    else:
        yield MagicMock() # Return dummy mock if features module unavailable

@pytest.fixture
def sample_feature_list():
    """Provides a sample list of feature dictionaries with enough data points."""
    base_time = datetime.datetime(2025, 1, 1, 10, 0, 0, tzinfo=datetime.timezone.utc)
    num_points = ml_engine.MIN_SAMPLES_FOR_TRAINING + 5 # Ensure enough points
    features_list = []

    for i in range(num_points):
        ts = base_time + datetime.timedelta(hours=i)
        ts_str = ts.isoformat()
        boot_id = f"host1_boot{i//24}" # Simulate occasional reboots

        # Unit A data (some variation)
        features_list.append({
            "report_timestamp": ts_str, "boot_id": boot_id, "unit_name": "unitA.service",
            "source": "resource_analysis",
            "cpu_usage_nsec": (1 + i * 0.1) * 1e9,
            "mem_current_bytes": (100 + i * 5) * 1e6,
            "mem_peak_bytes": (110 + i * 5) * 1e6, # Add peak mem
            "io_read_bytes": (10 + i) * 1e6,
            "io_write_bytes": (1 + i * 0.2) * 1e6,
            "tasks_current": 5 + (i % 3)
        })
        # Unit A health (occasional flapping)
        features_list.append({
            "report_timestamp": ts_str, "boot_id": boot_id, "unit_name": "unitA.service",
            "source": "health_analysis",
            "is_failed": False,
            "is_flapping": i % 5 == 0, # Flaps every 5 hours
            "n_restarts": i if i % 5 == 0 else 0
        })

        # Unit B data (more stable)
        features_list.append({
            "report_timestamp": ts_str, "boot_id": boot_id, "unit_name": "unitB.service",
            "source": "resource_analysis",
            "cpu_usage_nsec": (2 + (i % 2) * 0.1) * 1e9,
            "mem_current_bytes": (200 - (i % 4) * 2) * 1e6,
            "mem_peak_bytes": 205 * 1e6, # Stable peak
            "io_read_bytes": 5e6,
            "io_write_bytes": 1e6,
            "tasks_current": 2
        })

    return features_list


@pytest.fixture
def sample_dataframe(sample_feature_list):
    """Provides a sample DataFrame prepared from feature list."""
    if not pd: pytest.skip("Pandas not available")
    df = pd.DataFrame(sample_feature_list)
    df['report_timestamp'] = pd.to_datetime(df['report_timestamp'])

    # FIX: Aggregate features for the same unit/timestamp before proceeding
    # Use mean for numeric, last for bool/string, sum for counts? Or first? Let's use first for simplicity.
    # This ensures one row per unit per timestamp after combining resource/health sources.
    # Define aggregation rules
    agg_rules = {}
    numeric_cols = [
        'cpu_usage_nsec', 'mem_current_bytes', 'mem_peak_bytes',
        'io_read_bytes', 'io_write_bytes', 'tasks_current',
        'n_restarts', 'boot_blame_sec'
    ]
    bool_cols = ['is_failed', 'is_flapping', 'is_problematic_socket', 'is_problematic_timer']
    string_cols = ['boot_id', 'source', 'resource_error', 'health_error']

    for col in df.columns:
        if col in ['unit_name', 'report_timestamp']:
            continue
        elif col in numeric_cols:
            agg_rules[col] = 'mean' # or 'first', 'last', 'sum' depending on desired behavior
        elif col in bool_cols:
            agg_rules[col] = 'max' # Treat True as 1, False as 0. Max finds if *any* entry was True.
        else: # String or other types
            agg_rules[col] = 'first'

    df_agg = df.groupby(['unit_name', 'report_timestamp'], as_index=False, sort=False).agg(agg_rules)


    # Convert types after aggregation
    for col in bool_cols:
         if col in df_agg.columns:
              # Ensure boolean conversion handles potential NaNs from aggregation
              df_agg[col] = df_agg[col].fillna(0).astype(bool) # Fill NaNs from agg and ensure bool

    for col in numeric_cols:
         if col in df_agg.columns:
              df_agg[col] = pd.to_numeric(df_agg[col], errors='coerce') # NaNs handled later

    df_agg = df_agg.sort_values(by=['unit_name', 'report_timestamp'])
    return df_agg

@pytest.fixture
def temp_model_dir_path(tmp_path):
    """Creates a temporary directory Path object for saving/loading models."""
    model_dir = tmp_path / "ml_models"
    model_dir.mkdir()
    return model_dir

# --- Test Cases ---

# Test Data Loading and Preparation
def test_load_and_prepare_data_success(mock_feature_loading, sample_feature_list, tmp_path):
    """Test loading data, passing the history directory path."""
    mock_history_dir = tmp_path / "hist" # Create a dummy history dir path
    mock_feature_loading.return_value = ["report1", "report2"] # Mock return from load_historical_data

    # Mock extract_features (assuming it's imported correctly now)
    with patch('sysdiag_analyzer.ml_engine.features.extract_features', return_value=sample_feature_list):
        df = ml_engine.load_and_prepare_data(history_dir=mock_history_dir, num_reports=2)

    assert isinstance(df, pd.DataFrame)
    assert not df.empty
    # Verify load_historical_data was called with the correct path
    mock_feature_loading.assert_called_once_with(history_dir=mock_history_dir, num_reports=2)

def test_load_and_prepare_data_no_history(mock_feature_loading, tmp_path):
    mock_history_dir = tmp_path / "hist"
    mock_feature_loading.return_value = [] # No reports found
    df = ml_engine.load_and_prepare_data(history_dir=mock_history_dir)
    assert df is None
    mock_feature_loading.assert_called_once_with(history_dir=mock_history_dir, num_reports=50) # Default num_reports

# Test Feature Engineering
def test_engineer_features_success(sample_dataframe):
    engineered_df = ml_engine.engineer_features(sample_dataframe.copy())
    assert isinstance(engineered_df, pd.DataFrame)
    # FIX: Remove checks for removed lag/diff features
    # assert 'cpu_usage_nsec_lag1' in engineered_df.columns
    # Check for expected columns and ensure no NaNs in core numeric/bool
    expected_cols = [
        'cpu_usage_nsec', 'mem_current_bytes', 'mem_peak_bytes',
        'io_read_bytes', 'io_write_bytes', 'tasks_current',
        'is_failed', 'is_flapping'
    ]
    for col in expected_cols:
         assert col in engineered_df.columns
         assert not engineered_df[col].isnull().any(), f"NaNs found in engineered column '{col}'"

# Test Model Persistence
def test_save_load_models(temp_model_dir_path):
    """Test saving and loading models using the provided path."""
    ml_engine._check_ml_dependencies()
    # Use MinMaxScaler instead of StandardScaler
    models_to_save = {"unitA.service": IsolationForest(n_estimators=10, random_state=42).fit([[1],[2]])}
    scalers_to_save = {"unitA.service": MinMaxScaler().fit([[1],[2]])} # Changed scaler type

    # Save using the temp path
    ml_engine.save_models(models_to_save, ml_engine.ANOMALY_MODEL_TYPE, temp_model_dir_path)
    # Use the updated scaler type constant
    ml_engine.save_models(scalers_to_save, ml_engine.SCALER_MODEL_TYPE, temp_model_dir_path)

    # Check files exist in the temp path using the sanitized name
    # FIX: Update filename based on _sanitize_filename replacing '.' with '_dot_'
    sanitized_name_stem = "unitA_dot_service"
    model_path = temp_model_dir_path / ml_engine.ANOMALY_MODEL_TYPE
    scaler_path = temp_model_dir_path / ml_engine.SCALER_MODEL_TYPE
    assert (model_path / f"{sanitized_name_stem}.joblib").is_file()
    assert (scaler_path / f"{sanitized_name_stem}.joblib").is_file()

    # Load using the temp path
    loaded_models = ml_engine.load_models(ml_engine.ANOMALY_MODEL_TYPE, temp_model_dir_path)
    loaded_scalers = ml_engine.load_models(ml_engine.SCALER_MODEL_TYPE, temp_model_dir_path)

    assert len(loaded_models) == 1
    assert len(loaded_scalers) == 1
    # FIX: Check using the sanitized key used for loading
    assert sanitized_name_stem in loaded_models
    assert isinstance(loaded_models[sanitized_name_stem], IsolationForest)
    assert sanitized_name_stem in loaded_scalers # Check scaler loaded too
    assert isinstance(loaded_scalers[sanitized_name_stem], MinMaxScaler) # Check scaler type


def test_load_models_dir_not_found(tmp_path):
    """Test loading from a non-existent directory path."""
    non_existent_path = tmp_path / "non_existent_models"
    loaded_models = ml_engine.load_models("some_type", non_existent_path)
    assert loaded_models == {}

# Test Training
@patch('sysdiag_analyzer.ml_engine.save_models') # Mock save_models within train function
def test_train_anomaly_models_success(mock_save_models, sample_dataframe, temp_model_dir_path):
    """Test training, passing the model directory path."""
    # sample_dataframe fixture now provides enough data points per unit
    engineered_df = ml_engine.engineer_features(sample_dataframe)
    train_df = engineered_df # Use the engineered data directly

    # Call train, passing the temp path
    # FIX: Unpack 3 values now
    models, scalers, skipped_units = ml_engine.train_anomaly_models(train_df, temp_model_dir_path)

    assert len(models) == 2 # Should train for unitA and unitB
    assert len(scalers) == 2
    assert isinstance(skipped_units, list) # Check type of skipped_units
    # Check save_models was called with the correct path
    assert mock_save_models.call_count == 2
    mock_save_models.assert_any_call(models, ml_engine.ANOMALY_MODEL_TYPE, temp_model_dir_path)
    # FIX: Use updated scaler type constant
    mock_save_models.assert_any_call(scalers, ml_engine.SCALER_MODEL_TYPE, temp_model_dir_path)

# Test Anomaly Detection (No path arguments needed here)
@patch('sysdiag_analyzer.ml_engine.save_models') # Still need to mock saving within train
def test_detect_anomalies_success(mock_save_models_ignored, sample_dataframe, temp_model_dir_path):
    # 1. Engineer features on original data
    engineered_df_orig = ml_engine.engineer_features(sample_dataframe.copy())

    # 2. Train models using original engineered data
    # FIX: Unpack 3 values
    models, scalers, skipped_units = ml_engine.train_anomaly_models(engineered_df_orig, temp_model_dir_path)
    assert models, "Models should have been trained"
    assert scalers, "Scalers should have been trained"
    assert 'unitA.service' in models, "Model for unitA.service was not trained"
    assert 'unitA.service' in scalers, "Scaler for unitA.service was not trained"

    # 3. Get the features used by the scaler/model
    scaler_unitA = scalers['unitA.service']
    model_unitA = models['unitA.service']
    # FIX: Access feature names correctly
    training_features = list(getattr(scaler_unitA, 'feature_names_in_', []))
    assert training_features, "Scaler has no feature names stored"

    # 4. Select the *last* data point for unitA from the *original* engineered data
    last_point_unitA = engineered_df_orig[engineered_df_orig['unit_name'] == 'unitA.service'].iloc[[-1]].copy()

    # 5. Modify this single point to be anomalous
    anomalous_cpu_value = 1e12
    anomalous_mem_value = 5e9
    anomalous_tasks_value = 1000

    # Modify base features
    last_point_unitA['cpu_usage_nsec'] = anomalous_cpu_value
    last_point_unitA['mem_current_bytes'] = anomalous_mem_value
    last_point_unitA['tasks_current'] = anomalous_tasks_value
    last_point_unitA['is_failed'] = True # Make it failed

    # --- FIX: Lag/diff features removed, no need to modify them ---
    # Ensure required features exist before selecting
    missing_cols = [f for f in training_features if f not in last_point_unitA.columns]
    if missing_cols:
        for col in missing_cols:
            last_point_unitA[col] = 0 # Add missing with default 0

    # Fill any remaining NaNs in this single row (shouldn't be many after engineering)
    last_point_unitA_filled = last_point_unitA.fillna(0)

    # 6. Select only the training features for scaling and prediction
    # Make a copy to avoid SettingWithCopyWarning later
    features_for_prediction = last_point_unitA_filled[training_features].copy()

    # 7. Scale the anomalous point
    # FIX 2: Convert boolean columns to int *before* scaling, directly on the copy
    for col in ['is_failed', 'is_flapping']:
        if col in features_for_prediction.columns:
            # Directly assign the converted Series back to the column on the copy
            features_for_prediction[col] = features_for_prediction[col].astype(int)

    scaled_features = scaler_unitA.transform(features_for_prediction)

    # 8. Predict and get score
    prediction = model_unitA.predict(scaled_features)[0]
    score = model_unitA.score_samples(scaled_features)[0]

    print(f"\nDEBUG: Anomalous Point Features (Before Scaling):\n{features_for_prediction.to_string()}")
    print(f"DEBUG: Scaled Features:\n{scaled_features}")
    print(f"DEBUG: Prediction: {prediction}, Score: {score}")

    # 9. Assertions
    assert prediction == -1, f"Expected prediction -1 (anomaly) but got {prediction}"
    assert score < 0, f"Expected negative score for anomaly but got {score}"

    # Optional: Check the detect_anomalies function with this single point
    # Create a DataFrame suitable for detect_anomalies input
    detection_df = last_point_unitA_filled.copy() # Already has unit_name from reset_index earlier
    # Ensure unit_name column exists if it was dropped by selection
    if 'unit_name' not in detection_df.columns:
         detection_df['unit_name'] = 'unitA.service'

    # --- FIX: Pass models/scalers keyed by SANITIZED names to detect_anomalies ---
    safe_models = {ml_engine._sanitize_filename(k): v for k, v in models.items()}
    safe_scalers = {ml_engine._sanitize_filename(k): v for k, v in scalers.items()}
    anomalies = ml_engine.detect_anomalies(detection_df, safe_models, safe_scalers)
    assert len(anomalies) == 1, "detect_anomalies function failed to find the single anomaly"
    assert anomalies[0].unit_name == 'unitA.service'


# ... other detect_anomalies tests remain the same ...
