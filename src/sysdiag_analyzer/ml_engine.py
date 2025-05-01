# src/sysdiag_analyzer/ml_engine.py
from __future__ import annotations

import logging
import os
import pathlib
import re # Import re for filename sanitization consistency
import pprint # Import pprint for debugging raw features
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional

# Conditional imports for ML libraries
try:
    import numpy as np # Import numpy for variance check
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    # Phase 10 Fix 2: Use MinMaxScaler instead of StandardScaler
    from sklearn.preprocessing import MinMaxScaler
    import joblib
    HAS_ML_LIBS = True
    DataFrame = pd.DataFrame # Define DataFrame alias
except ImportError:
    HAS_ML_LIBS = False
    np = None # type: ignore
    pd = None # type: ignore
    IsolationForest = None # type: ignore
    # Define dummy scaler if import fails
    MinMaxScaler = None # type: ignore
    joblib = None # type: ignore
    DataFrame = Any

# Local imports
try:
    from . import features
    from .datatypes import MLAnalysisResult, AnomalyInfo
except ImportError:
    features = None # type: ignore
    MLAnalysisResult = Any # type: ignore
    AnomalyInfo = Any # type: ignore


log_ml = logging.getLogger(__name__)

# --- Configuration (Defaults, can be overridden by main using APP_CONFIG) ---
ANOMALY_MODEL_TYPE = "anomaly_isolationforest"
# Phase 10 Fix 2: Update scaler type name
SCALER_MODEL_TYPE = "scaler_minmax"
MIN_SAMPLES_FOR_TRAINING = 10
DEFAULT_ISOLATION_FOREST_CONTAMINATION = 'auto'
# DEBUGGING: Limit raw features to print
DEBUG_RAW_FEATURE_LIMIT = 20

# --- Helper Functions ---

def _check_ml_dependencies():
    """Checks if required ML libraries are installed."""
    if not HAS_ML_LIBS:
        msg = "ML libraries (pandas, scikit-learn, joblib, numpy) are not installed. ML features unavailable. Install with 'pip install sysdiag-analyzer[ml]'"
        log_ml.error(msg)
        raise ImportError(msg)
    # Phase 10 Fix 2: Check specific scaler
    if MinMaxScaler is None:
        msg = "MinMaxScaler could not be imported from scikit-learn. ML features unavailable."
        log_ml.error(msg)
        raise ImportError(msg)


def _sanitize_filename(name: str) -> str:
    """Creates a filesystem-safe filename from a unit name."""
    # Keep alphanumeric, underscore, hyphen. Replace others with underscore.
    # Similar logic used implicitly by joblib? Let's be explicit.
    # Replace common problematic chars like '.', '/', ':'
    name = name.replace('.', '_dot_') # Avoid ambiguity with file extensions
    name = name.replace('/', '_slash_')
    name = name.replace(':', '_colon_')
    # Replace any remaining non-safe characters
    safe_name = re.sub(r'[^\w-]', '_', name)
    # Avoid names starting with '-' or '_' if possible, prepend 'unit_' if so
    if safe_name.startswith(('-', '_')):
        safe_name = 'unit_' + safe_name
    return safe_name


# --- Model Persistence ---

def save_models(models: Dict[str, Any], model_type: str, model_storage_path: Path):
    """Saves trained models (or scalers) to disk using joblib."""
    _check_ml_dependencies()
    if not models:
        log_ml.warning(f"No models provided to save for type '{model_type}'.")
        return

    specific_model_path = model_storage_path / model_type
    try:
        specific_model_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        log_ml.info(f"Ensured model directory exists: {specific_model_path}")
    except PermissionError:
        log_ml.error(f"Permission denied creating model directory: {specific_model_path}")
        raise
    except Exception as e:
        log_ml.error(f"Error creating model directory {specific_model_path}: {e}")
        raise

    saved_count = 0
    error_count = 0
    # The keys in the 'models' dict are the ORIGINAL unit names
    for unit_name, model_obj in models.items():
        # Sanitize the original unit name ONLY for the filename
        safe_filename_stem = _sanitize_filename(unit_name)
        safe_filename = safe_filename_stem + ".joblib"
        filepath = specific_model_path / safe_filename
        try:
            joblib.dump(model_obj, filepath)
            saved_count += 1
            log_ml.debug(f"Saved model for '{unit_name}' (as {safe_filename})")
        except Exception as e:
            log_ml.error(f"Failed to save model for unit '{unit_name}' to {filepath}: {e}", exc_info=True)
            error_count += 1

    log_ml.info(f"Finished saving models for type '{model_type}'. Saved: {saved_count}, Errors: {error_count}")
    if error_count > 0:
        pass # Consider raising an exception or returning status


def load_models(model_type: str, model_storage_path: Path) -> Dict[str, Any]:
    """
    Loads models (or scalers) of a specific type from disk.
    The returned dictionary is keyed by the SANITIZED unit name (filename stem).
    """
    _check_ml_dependencies()
    models = {}
    specific_model_path = model_storage_path / model_type
    log_ml.info(f"Attempting to load models of type '{model_type}' from {specific_model_path}...")

    if not specific_model_path.is_dir():
        log_ml.warning(f"Model directory not found: {specific_model_path}. No models loaded.")
        return models

    loaded_count = 0
    error_count = 0
    for filepath in specific_model_path.glob("*.joblib"):
        try:
            model_obj = joblib.load(filepath)
            # Use the filename stem (sanitized name) as the key
            sanitized_key = filepath.stem
            models[sanitized_key] = model_obj
            loaded_count += 1
            log_ml.debug(f"Loaded model with key '{sanitized_key}' from {filepath}")
        except Exception as e:
            log_ml.error(f"Failed to load model from {filepath}: {e}", exc_info=True)
            error_count += 1

    log_ml.info(f"Finished loading models for type '{model_type}'. Loaded: {loaded_count}, Errors: {error_count}")
    return models

# --- Data Preparation and Feature Engineering ---

def load_and_prepare_data(history_dir: Path, num_reports: int = 50) -> Optional[DataFrame]:
    """Loads historical data, extracts features, and prepares a DataFrame."""
    _check_ml_dependencies()
    if not features:
        log_ml.error("Feature extraction module not available.")
        return None

    log_ml.info(f"Loading historical data for ML from {history_dir} (last {num_reports} reports)...")
    historical_reports = features.load_historical_data(history_dir=history_dir, num_reports=num_reports)
    if not historical_reports:
        log_ml.warning("No historical reports found or loaded. Cannot prepare ML data.")
        return None

    log_ml.info("Extracting features from historical reports...")
    flat_features = features.extract_features(historical_reports)
    if not flat_features:
        log_ml.warning("No features extracted from historical reports.")
        return None

    # --- DEBUGGING: Print sample of raw features removed for brevity ---

    log_ml.info("Converting features to DataFrame...")
    try:
        if pd is None: _check_ml_dependencies()
        df = pd.DataFrame(flat_features)

        # --- DEBUGGING: Check columns right after DataFrame creation removed ---

        if 'report_timestamp' not in df.columns:
             log_ml.error("DataFrame missing 'report_timestamp' column.")
             return None
        df['report_timestamp'] = pd.to_datetime(df['report_timestamp'], errors='coerce')
        df = df.dropna(subset=['report_timestamp'])

        # Convert boolean flags (ensure they exist before conversion)
        bool_cols = ['is_failed', 'is_flapping', 'is_problematic_socket', 'is_problematic_timer']
        for col in bool_cols:
             if col in df.columns:
                  # Convert to float first to handle potential non-boolean values, then bool
                  df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(bool)
             else:
                  # Add missing boolean columns if needed
                  log_ml.debug(f"Adding missing boolean column '{col}' with False during prepare.")
                  df[col] = False


        # Convert numeric columns (ensure they exist)
        numeric_cols = [
            'cpu_usage_nsec', 'mem_current_bytes', 'mem_peak_bytes',
            'io_read_bytes', 'io_write_bytes', 'tasks_current',
            'n_restarts', 'boot_blame_sec'
        ]
        for col in numeric_cols:
             if col in df.columns:
                  df[col] = pd.to_numeric(df[col], errors='coerce') # NaNs will be handled later by engineer_features
             else:
                  # Add missing numeric columns if needed
                  log_ml.debug(f"Adding missing numeric column '{col}' with NaN during prepare.")
                  df[col] = np.nan # Add as NaN initially


        # Aggregate features: Group by unit and timestamp, taking the first value
        # This combines resource/health/boot features for the same unit at the same time
        # We should ideally do this *before* type conversion? No, do it after.
        # Define aggregation rules
        agg_rules = {}
        columns_to_agg = df.columns.difference(['unit_name', 'report_timestamp'])
        for col in columns_to_agg:
             # Use 'first' as a simple strategy. Could use mean, max etc. if needed
             agg_rules[col] = 'first'

        # Check if unit_name column exists before grouping
        if 'unit_name' in df.columns:
            df_agg = df.groupby(['unit_name', 'report_timestamp'], as_index=False, sort=False).agg(agg_rules)
        else:
            log_ml.error("DataFrame missing 'unit_name' column before aggregation.")
            return None

        df_agg = df_agg.sort_values(by=['unit_name', 'report_timestamp'])
        log_ml.info(f"Prepared DataFrame after aggregation with shape {df_agg.shape} and columns: {df_agg.columns.tolist()}")
        return df_agg

    except Exception as e:
        log_ml.error(f"Error creating or preparing DataFrame: {e}", exc_info=True)
        return None


def engineer_features(df: DataFrame) -> DataFrame:
    """
    Performs feature engineering. Fills NaNs in numeric columns.
    Phase 10 Fix: Removed lag/diff features for simplicity.
    """
    _check_ml_dependencies()
    if df is None or df.empty:
        log_ml.warning("Cannot engineer features: Input DataFrame is empty or None.")
        return pd.DataFrame() if pd else None

    log_ml.info("Performing feature engineering (Phase 10: No lag/diff)...")
    # Basic features to ensure correct types and fill NaNs
    metrics_to_check = [
        'cpu_usage_nsec', 'mem_current_bytes', 'mem_peak_bytes', # Added peak mem
        'io_read_bytes', 'io_write_bytes', 'tasks_current'
    ]
    health_flags = ['is_failed', 'is_flapping']
    df_out = df.copy()

    # Ensure numeric types and fill NaNs for core metrics
    for col in metrics_to_check:
        if col in df_out.columns:
            # Fill NaNs with 0 *before* checking type
            df_out[col] = pd.to_numeric(df_out[col], errors='coerce').fillna(0)
        else:
             log_ml.debug(f"Adding missing numeric feature column '{col}' with 0s during engineering.")
             df_out[col] = 0 # Add column if missing, filled with 0

    # Ensure boolean types for health flags
    for col in health_flags:
         if col in df_out.columns:
              # Fill NaNs with 0 *before* converting to bool
              df_out[col] = pd.to_numeric(df_out[col], errors='coerce').fillna(0).astype(bool)
         else:
              log_ml.debug(f"Adding missing boolean feature column '{col}' with False during engineering.")
              df_out[col] = False # Add column if missing, filled with False


    # --- REMOVED Lag/Diff Feature Calculation ---
    # log_ml.info("Skipping lag/diff feature engineering in Phase 10 ML fix.")
    # --- End REMOVED ---

    log_ml.info(f"Finished feature engineering. DataFrame shape: {df_out.shape}")
    return df_out

# --- Anomaly Detection ---

def train_anomaly_models(
    features_df: DataFrame,
    model_dir_path: Path
) -> Tuple[Dict[str, IsolationForest], Dict[str, MinMaxScaler], List[str]]: # Changed Scaler Type
    """
    Trains per-unit Isolation Forest models and MinMaxScaler scalers.
    Returns trained models, scalers, and a list of units skipped.
    Phase 10 Fix 2: Uses MinMaxScaler. Includes mem_peak_bytes.
    DEBUG 3: Removed full describe, rely on raw feature print earlier.
    """
    _check_ml_dependencies()
    models: Dict[str, IsolationForest] = {}
    scalers: Dict[str, MinMaxScaler] = {} # Changed Scaler Type
    skipped_units: List[str] = []

    if features_df is None or features_df.empty:
        log_ml.warning("Cannot train anomaly models: Feature DataFrame is empty.")
        return models, scalers, skipped_units

    # Phase 10 Fix 2: Use base numeric features + peak mem + boolean health flags
    numeric_features = [
        'cpu_usage_nsec', 'mem_current_bytes', 'mem_peak_bytes', # Added peak
        'io_read_bytes', 'io_write_bytes', 'tasks_current',
        # Include boolean flags converted to numeric (0/1) for training
        'is_failed', 'is_flapping'
    ]
    # Ensure only features actually present in the DataFrame are used
    training_features = [f for f in numeric_features if f in features_df.columns]

    if not training_features:
        log_ml.error("No suitable base features found in the DataFrame for training.")
        return models, scalers, skipped_units

    log_ml.info(f"Starting anomaly model training for {features_df['unit_name'].nunique()} units using features: {training_features}")
    trained_count = 0
    skipped_insufficient_data = 0
    skipped_zero_variance = 0

    # --- REMOVED DEBUGGING 2 ---

    for unit_name, unit_data in features_df.groupby('unit_name'):
        log_ml.debug(f"Processing unit: {unit_name} (Data points: {len(unit_data)})")
        # Select only the training features
        unit_features_df = unit_data[training_features].copy()

        # Convert boolean columns to int (0/1) before scaling
        for col in ['is_failed', 'is_flapping']:
            if col in unit_features_df.columns:
                unit_features_df[col] = unit_features_df[col].astype(int)

        # Fill NaNs *before* scaling during training
        # This should have been done in engineer_features, but do it again just in case
        unit_features_df = unit_features_df.fillna(0)

        if len(unit_features_df) < MIN_SAMPLES_FOR_TRAINING:
            log_ml.info(f"Skipping training for unit '{unit_name}': Insufficient data ({len(unit_features_df)} < {MIN_SAMPLES_FOR_TRAINING}).")
            skipped_insufficient_data += 1
            continue

        try:
            # Check for zero variance *before* scaling (more informative)
            # Use np.ptp (peak-to-peak) which is max - min
            # Ensure we handle potential all-NaN columns if fillna didn't catch them
            if np and np.all(np.ptp(np.nan_to_num(unit_features_df.values), axis=0) == 0):
                 log_ml.info(f"Skipping training for unit '{unit_name}': All features have zero variance (unit likely stable/inactive).")
                 skipped_zero_variance += 1
                 skipped_units.append(unit_name)
                 continue

            # Phase 10 Fix 2: Use MinMaxScaler
            scaler = MinMaxScaler()
            # Fit scaler on the (potentially NaN-filled) data
            scaled_features_np = scaler.fit_transform(unit_features_df)

            # Store feature names AFTER fitting
            # Use .columns directly as it's guaranteed to exist and be correct here
            scaler.feature_names_in_ = list(unit_features_df.columns) # Store the columns used
            log_ml.debug(f"Scaler for {unit_name} trained with features: {scaler.feature_names_in_}")

            # Use original unit_name as the key for the dictionaries
            scalers[unit_name] = scaler

            model = IsolationForest(contamination=DEFAULT_ISOLATION_FOREST_CONTAMINATION, random_state=42)
            # Fit on the scaled data (MinMaxScaler handles constant features)
            model.fit(scaled_features_np)

            # Use original unit_name as the key
            models[unit_name] = model
            trained_count += 1
            log_ml.debug(f"Successfully trained model for unit: {unit_name}")

        except Exception as e:
            log_ml.error(f"Failed to train model for unit '{unit_name}': {e}", exc_info=True)
            if unit_name in models: del models[unit_name]
            if unit_name in scalers: del scalers[unit_name]

    log_ml.info(f"Finished anomaly model training. Trained: {trained_count}, Skipped (Insufficient Data): {skipped_insufficient_data}, Skipped (Zero Variance): {skipped_zero_variance}")

    # Save models using the original unit names as keys
    if models:
        try: save_models(models, ANOMALY_MODEL_TYPE, model_dir_path)
        except Exception as e: log_ml.error(f"Error saving anomaly models to {model_dir_path}: {e}")
    if scalers:
        try: save_models(scalers, SCALER_MODEL_TYPE, model_dir_path) # Uses updated SCALER_MODEL_TYPE
        except Exception as e: log_ml.error(f"Error saving scalers to {model_dir_path}: {e}")

    return models, scalers, skipped_units


def detect_anomalies(
    current_features_df: DataFrame,
    models: Dict[str, IsolationForest], # Expect keys to be SANITIZED names
    scalers: Dict[str, MinMaxScaler] # Expect keys to be SANITIZED names, # Changed Scaler Type
) -> List[AnomalyInfo]:
    """
    Detects anomalies in the latest features using pre-trained models.
    Phase 10 Fix 2: Uses MinMaxScaler. Ensures key consistency. Uses updated features.
    """
    _check_ml_dependencies()
    anomalies: List[AnomalyInfo] = []

    if current_features_df is None or current_features_df.empty:
        log_ml.warning("Cannot detect anomalies: Current features DataFrame is empty.")
        return anomalies
    if not models:
        log_ml.warning("Cannot detect anomalies: No pre-trained models provided.")
        return anomalies

    if 'unit_name' not in current_features_df.columns:
         log_ml.error("Current features DataFrame missing 'unit_name' column.")
         return anomalies
    # Use unit_name as index for easier lookup
    # Use copy() to avoid SettingWithCopyWarning if df is a slice
    current_features_df = current_features_df.set_index('unit_name', drop=False).copy()

    # Determine inference features from the first loaded scaler
    inference_features: Optional[List[str]] = None
    if scalers:
        first_scaler_key = next(iter(scalers.keys()), None)
        if first_scaler_key:
             first_scaler = scalers[first_scaler_key]
             # Check attribute exists before accessing
             if hasattr(first_scaler, 'feature_names_in_') and first_scaler.feature_names_in_ is not None:
                 inference_features = list(first_scaler.feature_names_in_)
                 log_ml.debug(f"Determined inference features from scaler '{first_scaler_key}': {inference_features}")
             else:
                 # Fallback if feature_names_in_ wasn't stored
                 # Use the simplified feature list directly
                 numeric_features = [
                     'cpu_usage_nsec', 'mem_current_bytes', 'mem_peak_bytes', # Added peak
                     'io_read_bytes', 'io_write_bytes', 'tasks_current',
                     'is_failed', 'is_flapping'
                 ]
                 inference_features = [f for f in numeric_features if f in current_features_df.columns]
                 log_ml.warning(f"Could not get exact feature names from scaler '{first_scaler_key}', using default base features: {inference_features}")
        else:
             log_ml.warning("Scalers dictionary is empty, cannot determine inference features.")


    if not inference_features:
        log_ml.error("Could not determine features used for training. Cannot perform inference.")
        return anomalies

    # Ensure all required features exist in the input DataFrame
    missing_features = [f for f in inference_features if f not in current_features_df.columns]
    if missing_features:
         # Add the missing features with default value 0 before proceeding
         log_ml.warning(f"Current features DataFrame is missing columns for inference: {missing_features}. Adding them with value 0.")
         for f in missing_features:
              current_features_df[f] = 0
         # Re-set index if adding columns removed it
         if 'unit_name' in current_features_df.columns and current_features_df.index.name != 'unit_name':
              current_features_df = current_features_df.set_index('unit_name', drop=False)


    log_ml.info(f"Detecting anomalies for {len(current_features_df)} units using features: {inference_features}")
    detected_count = 0

    for unit_name in current_features_df.index:
        # Generate the SANITIZED key for lookup, matching how models were loaded
        sanitized_key = _sanitize_filename(unit_name)

        if sanitized_key not in models or sanitized_key not in scalers:
            log_ml.debug(f"No trained model or scaler found for unit '{unit_name}' (key: '{sanitized_key}'), skipping anomaly detection.")
            continue

        try:
            model = models[sanitized_key]
            scaler = scalers[sanitized_key]

            # Select only the inference features in the correct order
            features_row_df = current_features_df.loc[[unit_name], inference_features].copy() # Use .loc for safety

            # Convert boolean columns to int (0/1) before scaling
            for col in ['is_failed', 'is_flapping']:
                if col in features_row_df.columns:
                    features_row_df[col] = features_row_df[col].astype(int)

            # Fill NaNs *before* scaling for prediction consistency with training
            unit_features_df_filled = features_row_df.fillna(0)

            # Ensure columns match exactly what the scaler expects
            # This should be handled by selecting inference_features correctly
            # unit_features_df_filled = unit_features_df_filled[inference_features] # Ensure order

            # Transform using the DataFrame
            scaled_features = scaler.transform(unit_features_df_filled)

            prediction = model.predict(scaled_features)[0]
            score = model.score_samples(scaled_features)[0]

            log_ml.debug(f"Unit: {unit_name}, Prediction: {prediction}, Score: {score:.4f}")

            # Check if prediction is -1 (anomaly)
            if prediction == -1:
                if AnomalyInfo:
                    anomalies.append(AnomalyInfo(unit_name=unit_name, score=score))
                detected_count += 1
                # Log at INFO level only if score is significantly low? Or always? Let's keep it for now.
                log_ml.info(f"Anomaly detected for unit '{unit_name}' (Prediction: {prediction}, Score: {score:.4f})")

        except ValueError as ve:
             # Catch errors related to feature mismatches during transform/predict
             log_ml.error(f"ValueError during anomaly detection for unit '{unit_name}' (likely feature mismatch): {ve}", exc_info=True)
        except Exception as e:
            log_ml.error(f"Error detecting anomalies for unit '{unit_name}': {e}", exc_info=True)

    log_ml.info(f"Finished anomaly detection. Found {detected_count} potential anomalies.")
    return anomalies
