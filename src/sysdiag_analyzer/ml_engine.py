# src/sysdiag_analyzer/ml_engine.py
from __future__ import annotations

import json
import logging
import re
import gc  # Import the garbage collector module
import collections
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set
from concurrent.futures import ProcessPoolExecutor, as_completed

# --- Suppress TensorFlow and Keras Verbose Logging ---
# Set TF log level via environment variable to hide C++ level messages
import os

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"  # 0=all, 1=info, 2=warning, 3=error

# Set Python logging level for TensorFlow to hide Python-level warnings like retracing
logging.getLogger("tensorflow").setLevel(logging.ERROR)


# Conditional imports for ML libraries
try:
    import numpy as np
    import pandas as pd
    from sklearn.preprocessing import MinMaxScaler
    import joblib

    import tensorflow as tf
    from tensorflow import keras

    HAS_ML_LIBS = True
    DataFrame = pd.DataFrame  # Define DataFrame alias
except ImportError:
    HAS_ML_LIBS = False
    np = None
    pd = None
    MinMaxScaler = None
    joblib = None
    tf = None
    keras = None
    DataFrame = Any

# Define logger early
log_ml = logging.getLogger(__name__)

# Local imports
try:
    from . import features
except ImportError as e:
    features = None
    log_ml.error(
        f"Failed to import 'features' module, ML features will be limited. Error: {e}"
    )

try:
    from .datatypes import AnomalyInfo, MLAnalysisResult
except ImportError:
    AnomalyInfo = Any
    MLAnalysisResult = Any


# --- Configuration (Defaults, can be overridden by main) ---
MIN_SAMPLES_FOR_TRAINING = 10
LSTM_TIMESTEPS = 5
# A sensible minimum threshold to prevent 0.0 thresholds for stable units
MINIMUM_THRESHOLD = 0.01


# --- Helper Functions ---
def _check_ml_dependencies():
    """Checks if required ML libraries are installed."""
    if not HAS_ML_LIBS:
        msg = "ML libraries (pandas, scikit-learn, tensorflow, joblib) are not installed. ML features unavailable. Install with 'pip install sysdiag-analyzer[ml]'"
        log_ml.error(msg)
        raise ImportError(msg)


def _sanitize_filename(name: str) -> str:
    """Creates a filesystem-safe filename from a unit name."""
    name = name.replace(".", "_dot_")
    name = name.replace("/", "_slash_")
    name = name.replace(":", "_colon_")
    safe_name = re.sub(r"[^\w-]", "_", name)
    if safe_name.startswith(("-", "_")):
        safe_name = "unit_" + safe_name
    return safe_name


# --- Model and Data Persistence ---
def save_model_artifacts(
    model: Any,
    scaler: Any,
    threshold: float,
    unit_name: str,
    model_storage_path: Path,
):
    """Saves all artifacts for a single unit to a dedicated directory."""
    _check_ml_dependencies()
    safe_name = _sanitize_filename(unit_name)
    unit_model_dir = model_storage_path / safe_name
    unit_model_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    try:
        # Save Keras model to a single .keras file (Keras 3 standard)
        model.save(unit_model_dir / "model.keras")
        # Save scaler
        joblib.dump(scaler, unit_model_dir / "scaler.joblib")
        # Save threshold and other metadata
        with open(unit_model_dir / "metadata.json", "w") as f:
            json.dump({"threshold": threshold}, f)
        log_ml.debug(f"Saved all artifacts for '{unit_name}'.")
    except Exception as e:
        log_ml.error(
            f"Failed to save artifacts for unit '{unit_name}': {e}", exc_info=True
        )


def load_models(
    model_storage_path: Path, active_units: Optional[Set[str]] = None
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, float]]:
    """
    Loads model artifacts, optionally filtering for a specific set of active units.
    """
    _check_ml_dependencies()
    models, scalers, thresholds = {}, {}, {}
    if not model_storage_path.is_dir():
        log_ml.warning(
            f"Model directory not found: {model_storage_path}. No models loaded."
        )
        return models, scalers, thresholds

    sanitized_active_units = (
        {_sanitize_filename(name) for name in active_units} if active_units else None
    )

    log_ml.info(
        f"Scanning model directory {model_storage_path}..."
        f"{' Filtering for active units.' if sanitized_active_units else ''}"
    )

    for unit_dir in model_storage_path.iterdir():
        if unit_dir.is_dir():
            sanitized_key = unit_dir.name
            if sanitized_active_units and sanitized_key not in sanitized_active_units:
                log_ml.debug(f"Skipping model load for inactive/unknown unit: {sanitized_key}")
                continue

            model_path = unit_dir / "model.keras"
            scaler_path = unit_dir / "scaler.joblib"
            metadata_path = unit_dir / "metadata.json"

            if (
                model_path.is_file()
                and scaler_path.is_file()
                and metadata_path.is_file()
            ):
                try:
                    models[sanitized_key] = keras.models.load_model(model_path)
                    scalers[sanitized_key] = joblib.load(scaler_path)
                    with open(metadata_path, "r") as f:
                        metadata = json.load(f)
                        thresholds[sanitized_key] = metadata["threshold"]
                    log_ml.debug(f"Loaded artifacts for key '{sanitized_key}'.")
                except Exception as e:
                    log_ml.error(
                        f"Failed to load artifacts for key '{sanitized_key}': {e}",
                        exc_info=True,
                    )
    log_ml.info(
        f"Finished loading. Found {len(models)} models, {len(scalers)} scalers, and {len(thresholds)} thresholds."
    )
    return models, scalers, thresholds


# --- Data Preparation and Feature Engineering ---
def load_and_prepare_data(
    history_dir: Path, num_reports: int = 50, include_devices: bool = False
) -> Optional[DataFrame]:
    """Loads historical data and prepares it into a DataFrame."""
    _check_ml_dependencies()
    if features is None:
        log_ml.error("Feature extraction module is not available.")
        return None

    log_ml.info(f"Loading last {num_reports} historical reports...")
    historical_reports = features.load_historical_data(
        history_dir=history_dir, num_reports=num_reports
    )
    if not historical_reports:
        log_ml.warning("No historical reports found for training.")
        return None

    features_list = features.extract_features(
        historical_reports, include_devices=include_devices
    )
    if not features_list:
        log_ml.warning("No features extracted from historical reports.")
        return None

    df = pd.DataFrame(features_list)
    df["report_timestamp"] = pd.to_datetime(df["report_timestamp"], errors="coerce")
    df = df.dropna(subset=["report_timestamp"])

    agg_rules: Dict[str, Any] = {}
    numeric_cols = [
        "cpu_usage_nsec",
        "mem_current_bytes",
        "mem_peak_bytes",
        "io_read_bytes",
        "io_write_bytes",
        "tasks_current",
        "n_restarts",
        "boot_blame_sec",
    ]
    bool_cols = [
        "is_failed",
        "is_flapping",
        "is_problematic_socket",
        "is_problematic_timer",
    ]
    for col in df.columns:
        if col in ["unit_name", "report_timestamp"]:
            continue
        elif col in numeric_cols:
            agg_rules[col] = "mean"
        elif col in bool_cols:
            agg_rules[col] = "max"
        else:
            agg_rules[col] = "first"

    df_agg = df.groupby(["unit_name", "report_timestamp"], as_index=False).agg(
        agg_rules
    )
    df_agg = df_agg.sort_values(by=["unit_name", "report_timestamp"])

    log_ml.info(f"Data prepared. Shape: {df_agg.shape}")
    return df_agg


def _create_sequences(data: np.ndarray, timesteps: int) -> np.ndarray:
    """Converts a 2D array of features into 3D sequences."""
    X = []
    for i in range(len(data) - timesteps + 1):
        X.append(data[i : (i + timesteps)])
    return np.array(X)


def engineer_features(df: DataFrame) -> DataFrame:
    """Performs feature engineering. Fills NaNs and ensures correct types."""
    _check_ml_dependencies()
    if df is None or df.empty:
        log_ml.warning("Cannot engineer features: Input DataFrame is empty or None.")
        return pd.DataFrame()

    log_ml.info("Performing feature engineering...")
    df_out = df.copy()

    numeric_features = [
        "cpu_usage_nsec",
        "mem_current_bytes",
        "mem_peak_bytes",
        "io_read_bytes",
        "io_write_bytes",
        "tasks_current",
    ]
    bool_features = ["is_failed", "is_flapping"]

    for col in numeric_features:
        if col in df_out.columns:
            df_out[col] = pd.to_numeric(df_out[col], errors="coerce").fillna(0)
        else:
            df_out[col] = 0

    for col in bool_features:
        if col in df_out.columns:
            df_out[col] = (
                pd.to_numeric(df_out[col], errors="coerce").fillna(0).astype(bool)
            )
        else:
            df_out[col] = False

    log_ml.info(f"Finished feature engineering. DataFrame shape: {df_out.shape}")
    return df_out


# --- LSTM Autoencoder Anomaly Detection ---
def _build_lstm_autoencoder(timesteps: int, n_features: int) -> keras.Model:
    """Builds the Keras LSTM Autoencoder model using the functional API."""
    inputs = keras.Input(shape=(timesteps, n_features))
    encoded = keras.layers.LSTM(64, activation="relu", return_sequences=True)(inputs)
    encoded = keras.layers.LSTM(32, activation="relu", return_sequences=False)(encoded)
    encoded = keras.layers.RepeatVector(timesteps)(encoded)
    decoded = keras.layers.LSTM(32, activation="relu", return_sequences=True)(encoded)
    decoded = keras.layers.LSTM(64, activation="relu", return_sequences=True)(decoded)
    outputs = keras.layers.TimeDistributed(keras.layers.Dense(n_features))(decoded)
    model = keras.Model(inputs, outputs)
    model.compile(optimizer="adam", loss="mae")
    return model


def _train_single_unit_model(
    unit_name: str, unit_df: DataFrame, model_dir_path: Path
) -> Tuple[str, bool, Optional[str]]:
    """
    Worker function to train a model for a single unit. This is executed in a
    separate process.
    """
    # Force TensorFlow to use CPU only (system RAM) within this worker process.
    # This prevents CUDA out-of-memory errors on systems with limited VRAM.
    os.environ["CUDA_VISIBLE_DEVICES"] = "-1"

    # Ensure dependencies are checked inside the worker
    _check_ml_dependencies()

    log_ml.info(f"Worker[{os.getpid()}]: Starting training for '{unit_name}'.")

    try:
        numeric_features = [
            "cpu_usage_nsec",
            "mem_current_bytes",
            "mem_peak_bytes",
            "io_read_bytes",
            "io_write_bytes",
            "tasks_current",
            "is_failed",
            "is_flapping",
        ]
        training_features = [f for f in numeric_features if f in unit_df.columns]
        n_features = len(training_features)
        if n_features == 0:
            return unit_name, False, "No numeric features found."

        unit_features_df = unit_df[training_features].copy()
        unit_features_df[["is_failed", "is_flapping"]] = unit_features_df[
            ["is_failed", "is_flapping"]
        ].astype(int)

        if unit_features_df.var().sum() == 0:
            return unit_name, False, "Zero variance in feature data."

        scaler = MinMaxScaler()
        scaler.feature_names_in_ = training_features
        scaled_data = scaler.fit_transform(unit_features_df)

        X_train = _create_sequences(scaled_data, LSTM_TIMESTEPS)
        if X_train.shape[0] == 0:
            return unit_name, False, "Not enough data to form a single sequence."

        model = _build_lstm_autoencoder(LSTM_TIMESTEPS, n_features)
        model.fit(
            X_train,
            X_train,
            epochs=20,
            batch_size=32,
            verbose=0,
            callbacks=[
                keras.callbacks.EarlyStopping(monitor="loss", patience=3, verbose=0)
            ],
        )

        train_pred = model.predict(X_train, batch_size=32, verbose=0)
        train_mae_loss = np.mean(np.abs(train_pred - X_train), axis=1).flatten()

        calculated_threshold = np.percentile(train_mae_loss, 95) * 1.5
        threshold = max(calculated_threshold, MINIMUM_THRESHOLD)

        log_ml.info(
            f"Worker[{os.getpid()}]: Trained model for '{unit_name}'. Anomaly threshold set to {threshold:.6f}."
        )
        save_model_artifacts(model, scaler, threshold, unit_name, model_dir_path)

        return unit_name, True, None
    except Exception as e:
        log_ml.error(
            f"Worker[{os.getpid()}]: Exception during training for '{unit_name}': {e}",
            exc_info=True,
        )
        return unit_name, False, str(e)
    finally:
        # ** CRITICAL MEMORY RELEASE STEP **
        keras.backend.clear_session()
        gc.collect()


def train_anomaly_models(
    engineered_df: DataFrame, model_dir_path: Path, max_workers: int = 1
) -> Tuple[int, Dict[str, List[str]]]:
    """
    Trains per-unit LSTM Autoencoder models in parallel using a process pool.
    """
    _check_ml_dependencies()
    trained_count = 0
    skipped_summary: Dict[str, List[str]] = collections.defaultdict(list)

    log_ml.info("Grouping data by unit for parallel training...")
    grouped_df = engineered_df.groupby("unit_name")
    tasks_to_submit = [
        (name, group)
        for name, group in grouped_df
        if len(group) >= MIN_SAMPLES_FOR_TRAINING
    ]

    # Identify units that are skipped upfront due to insufficient samples
    all_units = set(engineered_df["unit_name"].unique())
    units_to_train = {name for name, group in tasks_to_submit}
    upfront_skipped_units = list(all_units - units_to_train)
    if upfront_skipped_units:
        reason_key = f"Insufficient data (< {MIN_SAMPLES_FOR_TRAINING} samples)"
        skipped_summary[reason_key].extend(upfront_skipped_units)
        log_ml.info(
            f"Skipping {len(upfront_skipped_units)} units upfront due to insufficient data."
        )

    if max_workers > 1:
        log_ml.info(
            f"Submitting {len(tasks_to_submit)} training tasks to {max_workers} worker processes..."
        )
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    _train_single_unit_model, name, group_df, model_dir_path
                ): name
                for name, group_df in tasks_to_submit
            }

            for future in as_completed(futures):
                unit_name = futures[future]
                try:
                    _, was_trained, reason = future.result()
                    if was_trained:
                        trained_count += 1
                    else:
                        reason_str = reason or "Unknown reason"
                        skipped_summary[reason_str].append(unit_name)
                        log_ml.info(
                            f"Skipping '{unit_name}' post-training: {reason_str}"
                        )
                except Exception as e:
                    log_ml.error(
                        f"Training failed for unit '{unit_name}' with an exception in the worker: {e}",
                        exc_info=True,
                    )
                    skipped_summary["Worker process exception"].append(unit_name)
    else:
        log_ml.info(
            f"Running {len(tasks_to_submit)} training tasks serially in the main process..."
        )
        for name, group_df in tasks_to_submit:
            try:
                _, was_trained, reason = _train_single_unit_model(
                    name, group_df, model_dir_path
                )
                if was_trained:
                    trained_count += 1
                else:
                    reason_str = reason or "Unknown reason"
                    skipped_summary[reason_str].append(name)
                    log_ml.info(f"Skipping '{name}' post-training: {reason_str}")
            except Exception as e:
                log_ml.error(
                    f"Training failed for unit '{name}' with an exception: {e}",
                    exc_info=True,
                )
                skipped_summary["Serial execution exception"].append(name)

    total_skipped = sum(len(units) for units in skipped_summary.values())
    log_ml.info(
        f"Training complete. Trained: {trained_count}, Skipped: {total_skipped}"
    )
    return trained_count, dict(skipped_summary)


def detect_anomalies(
    current_features_df: DataFrame,
    models: Dict[str, Any],
    scalers: Dict[str, Any],
    thresholds: Dict[str, float],
) -> List[AnomalyInfo]:
    _check_ml_dependencies()
    anomalies: List[AnomalyInfo] = []
    if current_features_df is None or current_features_df.empty:
        return anomalies

    # The incoming dataframe from a 'run' command is already deduplicated,
    # so no re-mapping is needed here.
    for unit_name, unit_data in current_features_df.groupby("unit_name"):
        sanitized_key = _sanitize_filename(unit_name)
        if sanitized_key not in models:
            continue

        if len(unit_data) < LSTM_TIMESTEPS:
            continue

        model, scaler, threshold = (
            models[sanitized_key],
            scalers[sanitized_key],
            thresholds[sanitized_key],
        )
        training_features = [
            f for f in scaler.feature_names_in_ if f in unit_data.columns
        ]
        unit_features_df = unit_data[training_features].copy()
        unit_features_df[["is_failed", "is_flapping"]] = unit_features_df[
            ["is_failed", "is_flapping"]
        ].astype(int)

        sequence_data = unit_features_df.tail(LSTM_TIMESTEPS)
        if len(sequence_data) < LSTM_TIMESTEPS:
            continue

        scaled_data = scaler.transform(sequence_data)
        X_test = np.expand_dims(scaled_data, axis=0)

        pred = model.predict(X_test, verbose=0)
        mae_loss = np.mean(np.abs(pred - X_test), axis=1).flatten()[0]

        if mae_loss > threshold:
            anomalies.append(AnomalyInfo(unit_name=unit_name, score=float(mae_loss)))
            log_ml.info(
                f"Anomaly detected for '{unit_name}': Reconstruction error {mae_loss:.4f} > threshold {threshold:.4f}"
            )

    return anomalies