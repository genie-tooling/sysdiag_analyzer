# -*- coding: utf-8 -*-
import logging
import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List

# Use tomllib if available (Python 3.11+), otherwise fall back to tomli
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None # type: ignore

log_cfg = logging.getLogger(__name__)

# Default configuration values
DEFAULT_CONFIG: Dict[str, Any] = {
    "llm": {
        "provider": None,
        "model": None,
        "host": None,
        "temperature": 0.2,
        "max_tokens": 1024,
        "context_window": 4096,
    },
    "history": {
        "directory": "/var/lib/sysdiag-analyzer/history",
        "max_files": 50,
    },
    "models": {
        "directory": "/var/lib/sysdiag-analyzer/models",
        "anomaly_contamination": "auto",
        "min_samples_train": 10,
    },
}

# Default configuration file search paths
DEFAULT_CONFIG_FILES: List[Path] = [
    Path("/etc/sysdiag-analyzer/config.toml"),
    Path(os.path.expanduser("~/.config/sysdiag-analyzer/config.toml")),
]

def _merge_configs(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merges override dict into base dict."""
    merged = base.copy()
    for key, value in override.items():
        if isinstance(value, dict) and key in merged and isinstance(merged[key], dict):
            merged[key] = _merge_configs(merged[key], value)
        else:
            merged[key] = value
    return merged

def load_config(config_path_override: Optional[Path] = None) -> Dict[str, Any]:
    """
    Loads configuration, merging defaults, system, user, and override files.

    Args:
        config_path_override: A specific config file path to load, bypassing
                              default search paths if provided.

    Returns:
        The final merged configuration dictionary.
    """
    config = DEFAULT_CONFIG.copy()

    if tomllib is None:
        log_cfg.warning(
            "TOML library (tomli for Python < 3.11) not found. "
            "Configuration file loading is disabled. Using defaults."
        )
        return config

    files_to_load: List[Path] = []
    loaded_files_log: List[str] = []

    if config_path_override:
        if config_path_override.is_file():
            log_cfg.info(f"Using specified config file: {config_path_override}")
            files_to_load = [config_path_override]
        else:
            log_cfg.error(f"Specified config file not found: {config_path_override}. Using defaults.")
            return config # Return defaults if override file not found
    else:
        # Use default search paths if no override provided
        files_to_load = DEFAULT_CONFIG_FILES

    for config_file in files_to_load:
        # Skip if we are using an override and this is not it
        if config_path_override and config_file != config_path_override:
            continue
        # Skip if we are using defaults and the file doesn't exist
        if not config_path_override and not config_file.is_file():
            log_cfg.debug(f"Default configuration file not found, skipping: {config_file}")
            continue

        log_cfg.info(f"Loading configuration from: {config_file}")
        try:
            with open(config_file, "rb") as f:
                file_config = tomllib.load(f)
                config = _merge_configs(config, file_config) # Merge loaded config over existing
                loaded_files_log.append(str(config_file))
        except tomllib.TOMLDecodeError as e:
            log_cfg.error(f"Error parsing configuration file {config_file}: {e}")
            # Decide: continue with potentially partial config or bail? Let's continue for now.
        except OSError as e:
            log_cfg.error(f"Error reading configuration file {config_file}: {e}")
        except Exception as e:
            log_cfg.exception(f"Unexpected error loading config file {config_file}: {e}")

    if loaded_files_log:
        log_cfg.info(f"Configuration loaded and merged from: {', '.join(loaded_files_log)}")
    elif not config_path_override: # Only log 'no files found' if not using override
        log_cfg.info("No default configuration files found. Using default settings.")

    log_cfg.debug(f"Final configuration loaded: {config}")
    return config
