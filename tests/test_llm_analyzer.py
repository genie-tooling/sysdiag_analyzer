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

# Conditional import for the OpenAI-compatible provider
try:
    import openai  # noqa: F401
    HAS_OPENAI = getattr(llm_analyzer, 'HAS_OPENAI', False)
except ImportError:
    HAS_OPENAI = False
    openai = None # type: ignore

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


# --- Real orchestration tests (only the Ollama network boundary is stubbed) ---

def test_create_llm_prompt_embeds_report_data(sample_report):
    """The prompt builder must embed actual report data, not just boilerplate."""
    prompt = llm_analyzer._create_llm_prompt(sample_report, "HIST-SUMMARY-MARKER")
    assert prompt.startswith("/no_think")          # provider directive preserved
    assert sample_report.hostname in prompt         # "test-host"
    assert "failed.service" in prompt               # real failed-unit name embedded
    assert "anomaly.service" in prompt              # real anomaly embedded
    assert "HIST-SUMMARY-MARKER" in prompt          # historical context spliced in


@pytest.mark.skipif(not HAS_OLLAMA, reason="Ollama library not installed")
def test_analyze_with_llm_real_orchestration(mock_ollama_client, sample_report, sample_llm_config, mock_history_dir_llm):
    """
    Exercise the REAL orchestration path end-to-end: real provider factory, real
    historical-summary generation (against an empty history dir), real prompt
    construction, and real Ollama response parsing. Only ollama.Client is stubbed,
    so this catches breakage the fully-mocked orchestration test cannot.
    """
    if mock_ollama_client is None:
        pytest.skip("Ollama client could not be mocked (library likely missing).")

    result = llm_analyzer.analyze_with_llm(sample_report, sample_llm_config, mock_history_dir_llm)

    assert result.error is None
    assert result.synthesis == "Generated synthesis."
    assert result.prompt_token_count == 50
    assert result.completion_token_count == 100
    assert result.provider_used == "ollama"
    assert result.model_used == "test-model:latest"

    # The real prompt builder ran and embedded report data before hitting the client.
    mock_ollama_client.generate.assert_called_once()
    sent_prompt = mock_ollama_client.generate.call_args.kwargs["prompt"]
    assert "test-host" in sent_prompt
    assert "failed.service" in sent_prompt


# --- OpenAI-compatible provider tests ---

@pytest.fixture
def mock_openai_client():
    """Mocks openai.OpenAI to return a canned chat completion."""
    if not getattr(llm_analyzer, 'HAS_OPENAI', False) or openai is None:
        yield None
        return
    with patch.object(llm_analyzer.openai, 'OpenAI') as mock_cls:
        instance = MagicMock()
        message = MagicMock()
        message.content = "OpenAI synthesis."
        choice = MagicMock()
        choice.message = message
        usage = MagicMock()
        usage.prompt_tokens = 42
        usage.completion_tokens = 84
        response = MagicMock()
        response.choices = [choice]
        response.usage = usage
        instance.chat.completions.create.return_value = response
        mock_cls.return_value = instance
        yield instance


@pytest.mark.skipif(not HAS_OPENAI, reason="openai library not installed")
def test_get_provider_openai_compatible(sample_llm_config):
    provider = llm_analyzer.LLMProvider.get_provider("openai", "gpt-4o-mini", sample_llm_config)
    assert isinstance(provider, llm_analyzer.OpenAICompatibleProvider)
    provider2 = llm_analyzer.LLMProvider.get_provider("openai-compatible", "local-model", sample_llm_config)
    assert isinstance(provider2, llm_analyzer.OpenAICompatibleProvider)


@pytest.mark.skipif(not HAS_OPENAI, reason="openai library not installed")
def test_openai_provider_generate_success(mock_openai_client):
    if mock_openai_client is None:
        pytest.skip("openai client could not be mocked.")
    provider = llm_analyzer.OpenAICompatibleProvider("gpt-4o-mini", {"host": "http://localhost:8000/v1"})
    synthesis, tokens, error = provider.generate("prompt", 0.2, 256, 4096)
    assert error is None
    assert synthesis == "OpenAI synthesis."
    assert tokens == {"prompt_tokens": 42, "completion_tokens": 84}
    call = mock_openai_client.chat.completions.create.call_args
    assert call.kwargs["model"] == "gpt-4o-mini"
    assert call.kwargs["messages"][0]["content"] == "prompt"
