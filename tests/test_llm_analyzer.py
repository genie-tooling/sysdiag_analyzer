# -*- coding: utf-8 -*-
import pytest
from unittest.mock import patch, MagicMock

# Module to test
from sysdiag_analyzer import llm_analyzer
from sysdiag_analyzer.datatypes import (
    SystemReport, LLMAnalysisResult, HealthAnalysisResult, UnitHealthInfo,
    MLAnalysisResult, AnomalyInfo
)

# Conditional import for Ollama
try:
    import ollama
    # Check if the module itself loaded HAS_OLLAMA flag correctly
    HAS_OLLAMA = getattr(llm_analyzer, 'HAS_OLLAMA', False)
except ImportError:
    HAS_OLLAMA = False
    ollama = None # type: ignore

# --- Fixtures ---

@pytest.fixture(autouse=True)
def check_deps():
    """Skip all tests in this module if LLM engine failed import."""
    # Check if the llm_analyzer module itself loaded successfully
    # by checking for an expected attribute (like the HAS_OLLAMA flag)
    if not hasattr(llm_analyzer, 'HAS_OLLAMA'):
        pytest.skip("Skipping LLM tests: llm_analyzer module failed import.", allow_module_level=True)

@pytest.fixture
def mock_ollama_client():
    """Mocks the ollama.Client."""
    # Check the flag defined within the llm_analyzer module
    if not getattr(llm_analyzer, 'HAS_OLLAMA', False) or ollama is None:
        yield None # Indicate mock is not available
        return

    # Patch the Client class within the imported ollama module reference
    with patch.object(ollama, 'Client', autospec=True) as mock_client_cls:
        mock_instance = MagicMock()
        mock_instance.generate.return_value = {
            "response": "Generated synthesis.", "prompt_eval_count": 50, "eval_count": 100,
        }
        mock_client_cls.return_value = mock_instance
        yield mock_instance

@pytest.fixture
def sample_report():
    """Provides a basic SystemReport object for testing."""
    return SystemReport(
        hostname="test-host", timestamp="2024-01-01T12:00:00Z", boot_id="test-boot-123",
        health_analysis=HealthAnalysisResult(failed_units=[UnitHealthInfo(name="failed.service")], all_units_count=10),
        ml_analysis=MLAnalysisResult(anomalies_detected=[AnomalyInfo(unit_name="anomaly.service", score=-0.2)])
    )

@pytest.fixture
def sample_llm_config():
    """Provides a sample LLM config dictionary."""
    return {
        "provider": "ollama", "model": "test-model:latest", "host": None,
        "temperature": 0.1, "max_tokens": 500, "context_window": 2048,
    }

@pytest.fixture
def mock_history_dir_llm(tmp_path):
    """Provides a temporary Path object for the history directory."""
    hist_dir = tmp_path / "llm_hist"
    hist_dir.mkdir()
    return hist_dir

@pytest.fixture
def mock_historical_data_llm(mock_history_dir_llm): # Depends on the temp dir fixture
    """Mocks features.load_historical_data returning specific data."""
    mock_history = [
        {"hostname": "test-host", "timestamp": "2024-01-01T11:00:00Z", "boot_id": "test-boot-123",
         "health_analysis": {"failed_units": [{"name": "failed.service"}]}},
        {"hostname": "test-host", "timestamp": "2024-01-01T10:00:00Z", "boot_id": "test-boot-123",
         "ml_analysis": {"anomalies_detected": [{"unit_name": "anomaly.service", "score": -0.3}]}},
    ]
    # Patch the function directly within the llm_analyzer module's namespace
    with patch('sysdiag_analyzer.llm_analyzer.load_historical_data', return_value=mock_history) as mock_load,          patch('sysdiag_analyzer.llm_analyzer.extract_features_from_report') as mock_extract:
        # Simplified side effect for extract
        def extract_side_effect(report_dict):
            features = []
            if report_dict.get("health_analysis", {}).get("failed_units"):
                for u in report_dict["health_analysis"]["failed_units"]:
                    features.append({"unit_name": u["name"], "source": "health_analysis", "is_failed": True})
            if report_dict.get("ml_analysis", {}).get("anomalies_detected"):
                 for a in report_dict["ml_analysis"]["anomalies_detected"]:
                    features.append({"unit_name": a["unit_name"], "source": "ml_analysis", "is_anomalous": True})
            return features
        mock_extract.side_effect = extract_side_effect
        yield mock_load, mock_extract # Yield mocks if needed

# --- Test Cases ---

# Test Historical Summary
def test_generate_historical_summary_found(sample_report, mock_historical_data_llm, mock_history_dir_llm):
    """Test generating summary, passing the history directory path."""
    mock_load, _ = mock_historical_data_llm # Get the mock loader
    # Call with the temp dir path
    summary = llm_analyzer._generate_historical_summary(sample_report, history_dir=mock_history_dir_llm, history_limit=2)
    assert "Summary of relevant issues" in summary
    assert "- Unit 'failed.service' showed issue 'failed' in 1 report(s)." in summary
    assert "- Unit 'anomaly.service' showed issue 'anomaly' in 1 report(s)." in summary
    # Verify load_historical_data was called with the correct path
    mock_load.assert_called_once_with(history_dir=mock_history_dir_llm, num_reports=2)

# Test Prompt Creation (No changes needed)
def test_create_llm_prompt(sample_report):
    history_summary = "Historical context: Unit 'failed.service' failed previously."
    prompt = llm_analyzer._create_llm_prompt(sample_report, history_summary)
    assert "**Role:**" in prompt
    assert history_summary in prompt

# Test Provider Factory (No changes needed)
@pytest.mark.skipif(not HAS_OLLAMA, reason="Ollama library not installed")
def test_get_provider_ollama_success(sample_llm_config):
    provider = llm_analyzer.LLMProvider.get_provider("ollama", "model", sample_llm_config)
    assert isinstance(provider, llm_analyzer.OllamaProvider)

# Test OllamaProvider Generate Method (No changes needed)
@pytest.mark.skipif(not HAS_OLLAMA, reason="Ollama library not installed")
def test_ollama_provider_generate_success(mock_ollama_client, sample_llm_config):
    # Ensure mock_ollama_client fixture ran successfully
    if mock_ollama_client is None:
        pytest.skip("Ollama client could not be mocked (library likely missing).")
    provider = llm_analyzer.OllamaProvider(sample_llm_config["model"], sample_llm_config)
    synthesis, tokens, error = provider.generate("prompt", 0.5, 100, 2048)
    assert error is None
    assert synthesis == "Generated synthesis."
    assert tokens == {"prompt_tokens": 50, "completion_tokens": 100}

# Test Main Orchestration Function
@patch('sysdiag_analyzer.llm_analyzer.LLMProvider.get_provider')
@patch('sysdiag_analyzer.llm_analyzer._generate_historical_summary', return_value="Mock history.")
@patch('sysdiag_analyzer.llm_analyzer._create_llm_prompt', return_value="Mock prompt.")
def test_analyze_with_llm_success(mock_create_prompt, mock_gen_history, mock_get_provider, sample_report, sample_llm_config, mock_history_dir_llm):
    """Test main LLM analysis function, passing the history directory path."""
    mock_provider_instance = MagicMock()
    mock_provider_instance.generate.return_value = ("LLM says hello!", {"prompt_tokens": 10, "completion_tokens": 5}, None)
    mock_get_provider.return_value = mock_provider_instance

    # Call with the temp dir path
    result = llm_analyzer.analyze_with_llm(sample_report, sample_llm_config, mock_history_dir_llm)

    assert isinstance(result, LLMAnalysisResult)
    assert result.error is None
    assert result.synthesis == "LLM says hello!"
    # Verify _generate_historical_summary was called with the correct path
    mock_gen_history.assert_called_once_with(sample_report, mock_history_dir_llm)
    mock_create_prompt.assert_called_once_with(sample_report, "Mock history.")
    mock_provider_instance.generate.assert_called_once()

# ... other analyze_with_llm tests remain similar, ensuring mock_history_dir_llm is passed ...
