# -*- coding: utf-8 -*-
import pytest
import sys
from unittest.mock import patch

# Module to test
from sysdiag_analyzer import config

# Use tomllib if available (Python 3.11+), otherwise fall back to tomli
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

# --- Fixtures ---

@pytest.fixture
def mock_default_config_files(tmp_path):
    """Creates mock default config files in a temporary directory."""
    sys_config_dir = tmp_path / "etc" / "sysdiag-analyzer"
    user_config_dir = tmp_path / "home" / "user" / ".config" / "sysdiag-analyzer"
    sys_config_dir.mkdir(parents=True)
    user_config_dir.mkdir(parents=True)

    sys_config_path = sys_config_dir / "config.toml"
    user_config_path = user_config_dir / "config.toml"

    # Write mock content
    sys_config_content = """
[llm]
provider = "ollama"
model = "llama3:latest" # System default model
temperature = 0.3

[history]
max_files = 100 # System override
directory = "/etc/sysdiag/history" # System path
"""
    user_config_content = """
# User overrides system settings
[llm]
model = "mistral:latest" # User prefers mistral
host = "http://10.0.0.5:11434" # User custom host

[models]
anomaly_contamination = 0.05 # User setting
directory = "/home/user/.sysdiag/models" # User path
"""
    sys_config_path.write_text(sys_config_content)
    user_config_path.write_text(user_config_content)

    # Patch DEFAULT_CONFIG_FILES and os.path.expanduser to use tmp_path
    with patch('sysdiag_analyzer.config.DEFAULT_CONFIG_FILES', [sys_config_path, user_config_path]), \
         patch('os.path.expanduser', lambda p: str(tmp_path / "home" / "user") if p == "~" else p):
        yield sys_config_path, user_config_path

@pytest.fixture
def mock_override_config_file(tmp_path):
    """Creates a mock override config file."""
    override_path = tmp_path / "override_config.toml"
    override_content = """
[llm]
provider = "override_provider"
model = "override_model"

[history]
directory = "/override/history"
max_files = 25
"""
    override_path.write_text(override_content)
    yield override_path


@pytest.fixture
def mock_no_config_files(tmp_path):
    """Ensures no default config files exist for testing defaults."""
    sys_config_path = tmp_path / "etc" / "sysdiag-analyzer" / "config.toml"
    user_config_path = tmp_path / "home" / "user" / ".config" / "sysdiag-analyzer" / "config.toml"
    # Ensure parent dirs exist but files don't
    sys_config_path.parent.mkdir(parents=True, exist_ok=True)
    user_config_path.parent.mkdir(parents=True, exist_ok=True)
    if sys_config_path.exists(): sys_config_path.unlink()
    if user_config_path.exists(): user_config_path.unlink()

    with patch('sysdiag_analyzer.config.DEFAULT_CONFIG_FILES', [sys_config_path, user_config_path]), \
         patch('os.path.expanduser', lambda p: str(tmp_path / "home" / "user") if p == "~" else p):
        yield


# --- Test Cases ---

@pytest.mark.skipif(tomllib is None, reason="TOML library (tomli) not installed")
def test_load_config_merging_defaults(mock_default_config_files):
    """Test successful loading and merging of system and user configs over defaults."""
    loaded_config = config.load_config() # No override path

    # Check merged values
    assert loaded_config["llm"]["provider"] == "ollama" # From system
    assert loaded_config["llm"]["model"] == "mistral:latest" # Overridden by user
    assert loaded_config["llm"]["temperature"] == 0.3 # From system (not overridden)
    assert loaded_config["llm"]["host"] == "http://10.0.0.5:11434" # From user
    # assert loaded_config["history"]["directory"] == "/home/user/.sysdiag/history" # INCORRECT assertion based on mock data
    assert loaded_config["history"]["max_files"] == 100 # Overridden by system (user didn't specify)
    assert loaded_config["models"]["directory"] == "/home/user/.sysdiag/models" # From user
    assert loaded_config["models"]["anomaly_contamination"] == 0.05 # From user
    # Check default values are still present if not overridden
    assert loaded_config["llm"]["max_tokens"] == config.DEFAULT_CONFIG["llm"]["max_tokens"]
    # Check history dir again based on mock files
    # Sys: dir=/etc/sysdiag/history, max=100
    # User: model=mistral, host=..., anomaly=0.05, models_dir=/home/user/.sysdiag/models
    # Expected history dir: /etc/sysdiag/history (from system, user didn't override)
    assert loaded_config["history"]["directory"] == "/etc/sysdiag/history" # From system

@pytest.mark.skipif(tomllib is None, reason="TOML library (tomli) not installed")
def test_load_config_with_override(mock_override_config_file, mock_default_config_files):
    """Test loading with a specific override file."""
    # mock_default_config_files ensures default files exist but shouldn't be read
    sys_path, user_path = mock_default_config_files

    loaded_config = config.load_config(config_path_override=mock_override_config_file)

    # Check values are from the override file or defaults
    assert loaded_config["llm"]["provider"] == "override_provider"
    assert loaded_config["llm"]["model"] == "override_model"
    assert loaded_config["history"]["directory"] == "/override/history"
    assert loaded_config["history"]["max_files"] == 25
    # Check defaults for non-overridden values
    assert loaded_config["llm"]["temperature"] == config.DEFAULT_CONFIG["llm"]["temperature"]
    assert loaded_config["models"]["directory"] == config.DEFAULT_CONFIG["models"]["directory"]

@pytest.mark.skipif(tomllib is None, reason="TOML library (tomli) not installed")
def test_load_config_override_not_found(tmp_path, caplog):
    """Test loading with an override file that doesn't exist."""
    override_path = tmp_path / "non_existent_config.toml"
    loaded_config = config.load_config(config_path_override=override_path)

    # Should return defaults and log an error
    assert loaded_config == config.DEFAULT_CONFIG
    assert f"Specified config file not found: {override_path}" in caplog.text

@pytest.mark.skipif(tomllib is None, reason="TOML library (tomli) not installed")
def test_load_config_only_system(tmp_path):
    """Test loading only the system config file when user file is absent."""
    sys_config_dir = tmp_path / "etc" / "sysdiag-analyzer"
    sys_config_dir.mkdir(parents=True)
    sys_config_path = sys_config_dir / "config.toml"
    user_config_path = tmp_path / "home" / "user" / ".config" / "sysdiag-analyzer" / "config.toml"

    sys_config_content = """
[llm]
provider = "ollama"
model = "system_model"
[history]
directory = "/system/history"
"""
    sys_config_path.write_text(sys_config_content)
    # Ensure user config does NOT exist
    if user_config_path.exists(): user_config_path.unlink()
    user_config_path.parent.mkdir(parents=True, exist_ok=True)

    with patch('sysdiag_analyzer.config.DEFAULT_CONFIG_FILES', [sys_config_path, user_config_path]), \
         patch('os.path.expanduser', lambda p: str(tmp_path / "home" / "user") if p == "~" else p):
        loaded_config = config.load_config()

    assert loaded_config["llm"]["provider"] == "ollama"
    assert loaded_config["llm"]["model"] == "system_model"
    assert loaded_config["history"]["directory"] == "/system/history" # From system
    assert loaded_config["history"]["max_files"] == config.DEFAULT_CONFIG["history"]["max_files"] # Default

@pytest.mark.skipif(tomllib is None, reason="TOML library (tomli) not installed")
def test_load_config_no_files(mock_no_config_files):
    """Test loading config when no default files exist."""
    loaded_config = config.load_config()
    assert loaded_config == config.DEFAULT_CONFIG

@pytest.mark.skipif(tomllib is None, reason="TOML library (tomli) not installed")
def test_load_config_parse_error(tmp_path, caplog):
    """Test handling of a malformed TOML file."""
    config_dir = tmp_path / "etc" / "sysdiag-analyzer"
    config_dir.mkdir(parents=True)
    config_path = config_dir / "config.toml"
    config_path.write_text("this is not valid toml = ") # Invalid content

    # Patch only the system path for this test
    with patch('sysdiag_analyzer.config.DEFAULT_CONFIG_FILES', [config_path]):
        loaded_config = config.load_config()

    # Should return defaults, and log an error
    assert loaded_config == config.DEFAULT_CONFIG
    assert f"Error parsing configuration file {config_path}" in caplog.text

@patch('sysdiag_analyzer.config.tomllib', None) # Simulate toml library not being installed
def test_load_config_no_toml_library(caplog):
    """Test behavior when the TOML parsing library is missing."""
    loaded_config = config.load_config()
    # Should return defaults and log a warning
    assert loaded_config == config.DEFAULT_CONFIG
    assert "TOML library (tomli for Python < 3.11) not found" in caplog.text
