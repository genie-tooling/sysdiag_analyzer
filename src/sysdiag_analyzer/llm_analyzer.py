# -*- coding: utf-8 -*-
from __future__ import annotations

import logging
import abc
from pathlib import Path # Import Path
from typing import Optional, Dict, Any, List, Tuple

# Conditional import for Ollama
try:
    import ollama
    HAS_OLLAMA = True
except ImportError:
    HAS_OLLAMA = False
    ollama = None # type: ignore

# Local imports
from .datatypes import SystemReport, LLMAnalysisResult
# Import necessary functions directly. If this fails, the module load fails.
from .features import load_historical_data, extract_features_from_report

log_llm = logging.getLogger(__name__)

# --- Constants ---
DEFAULT_LLM_TEMPERATURE = 0.2
DEFAULT_LLM_MAX_TOKENS = 1024
DEFAULT_LLM_CONTEXT_WINDOW = 4096
DEFAULT_HISTORY_SUMMARY_LIMIT = 5

# --- LLM Provider Abstraction ---

class LLMProvider(abc.ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, model: str, config: Dict[str, Any]):
        self.model = model
        self.config = config
        log_llm.info(f"Initializing LLMProvider: {self.__class__.__name__} with model: {model}")

    @abc.abstractmethod
    def generate(self, prompt: str, temperature: float, max_tokens: int, context_window: int) -> Tuple[Optional[str], Optional[Dict[str, int]], Optional[str]]:
        """Generates text based on the prompt using the specific provider."""
        pass

    @staticmethod
    def get_provider(provider_name: str, model: str, config: Dict[str, Any]) -> Optional[LLMProvider]:
        """Factory method to get an instance of the requested provider."""
        log_llm.info(f"Attempting to get LLM provider: {provider_name}")
        if provider_name == "ollama":
            if not HAS_OLLAMA:
                log_llm.error("Ollama provider requested, but 'ollama' library is not installed.")
                return None
            return OllamaProvider(model, config)
        else:
            log_llm.error(f"Unsupported LLM provider specified: {provider_name}")
            return None

# --- Ollama Provider Implementation ---

class OllamaProvider(LLMProvider):
    """LLM provider implementation for Ollama."""

    def generate(self, prompt: str, temperature: float, max_tokens: int, context_window: int) -> Tuple[Optional[str], Optional[Dict[str, int]], Optional[str]]:
        """Generates text using the Ollama API."""
        if not ollama:
             return None, None, "Ollama library not available."

        host = self.config.get("host")
        client_args = {"host": host} if host else {}

        try:
            client = ollama.Client(**client_args)
            log_llm.info(f"Sending request to Ollama model '{self.model}' (Host: {host or 'default'})...")

            options = {
                "temperature": temperature,
                "num_predict": max_tokens,
                "num_ctx": context_window,
            }

            response = client.generate(
                model=self.model,
                prompt=prompt,
                options=options,
                stream=False
            )

            synthesis = response.get("response")
            if not synthesis:
                return None, None, "Ollama response did not contain 'response' field."

            token_usage = None
            if "eval_count" in response and "prompt_eval_count" in response:
                token_usage = {
                    "prompt_tokens": response.get("prompt_eval_count"),
                    "completion_tokens": response.get("eval_count")
                }

            log_llm.info(f"Ollama generation successful. Completion tokens: {token_usage.get('completion_tokens', 'N/A') if token_usage else 'N/A'}")
            return synthesis.strip(), token_usage, None

        except ollama.ResponseError as e:
            err_msg = f"Ollama API error: {e.status_code} - {e.error}"
            log_llm.error(err_msg)
            if "model not found" in e.error.lower():
                err_msg += f". Make sure model '{self.model}' is available in Ollama (try 'ollama pull {self.model}')."
            return None, None, err_msg
        except Exception as e:
            err_msg = f"Error communicating with Ollama: {e}"
            log_llm.exception(err_msg)
            return None, None, err_msg


# --- Prompt Generation ---

def _generate_historical_summary(
    report: SystemReport,
    history_dir: Path,
    history_limit: int = DEFAULT_HISTORY_SUMMARY_LIMIT
) -> str:
    """Generates a concise text summary of relevant historical issues."""
    log_llm.debug(f"Generating historical summary from {history_dir} (limit: {history_limit} reports)...")
    summary_lines = []
    try:
        # REMOVED: if not features: check - Import success is sufficient
        historical_reports = load_historical_data(history_dir=history_dir, num_reports=history_limit)
        if not historical_reports:
            return "No historical reports found or loaded."

        current_problem_units = set()
        current_anomalous_units = set()
        current_log_patterns = set()

        if report.health_analysis:
            current_problem_units.update(u.name for u in report.health_analysis.failed_units)
            current_problem_units.update(u.name for u in report.health_analysis.flapping_units)
        if report.ml_analysis:
            current_anomalous_units.update(a.unit_name for a in report.ml_analysis.anomalies_detected)
        if report.log_analysis:
            current_log_patterns.update(p.pattern_key for p in report.log_analysis.detected_patterns)

        historical_counts: Dict[str, int] = {}

        for past_report in historical_reports:
            if not isinstance(past_report, dict): continue
            past_features = extract_features_from_report(past_report)
            past_units_failed = set()
            past_units_flapping = set()
            past_units_anomalous = set()
            past_log_patterns = set()

            for feature in past_features:
                unit = feature.get("unit_name")
                source = feature.get("source")
                if not unit: continue
                if source == "health_analysis":
                    if feature.get("is_failed"): past_units_failed.add(unit)
                    if feature.get("is_flapping"): past_units_flapping.add(unit)
                elif source == "ml_analysis":
                    # This depends on how past ML results are stored/extracted
                    # Assuming a hypothetical 'is_anomalous' flag for simplicity
                    if feature.get("is_anomalous"): past_units_anomalous.add(unit)
                elif source == "log_analysis":
                    pattern = feature.get("pattern_key")
                    if pattern: past_log_patterns.add(pattern)

            for unit in current_problem_units:
                if unit in past_units_failed: historical_counts[f"{unit}:failed"] = historical_counts.get(f"{unit}:failed", 0) + 1
                if unit in past_units_flapping: historical_counts[f"{unit}:flapping"] = historical_counts.get(f"{unit}:flapping", 0) + 1
            for unit in current_anomalous_units:
                if unit in past_units_anomalous: historical_counts[f"{unit}:anomaly"] = historical_counts.get(f"{unit}:anomaly", 0) + 1
            for pattern in current_log_patterns:
                if pattern in past_log_patterns: historical_counts[f"log:{pattern}"] = historical_counts.get(f"log:{pattern}", 0) + 1

        if not historical_counts:
            summary_lines.append("No relevant issues found in recent history.")
        else:
            summary_lines.append(f"Summary of relevant issues in the last {len(historical_reports)} reports:")
            for key, count in sorted(historical_counts.items()):
                if count > 0:
                    parts = key.split(":")
                    if parts[0] == "log": summary_lines.append(f"- Log pattern '{parts[1]}' appeared in {count} report(s).")
                    elif len(parts) == 2: summary_lines.append(f"- Unit '{parts[0]}' showed issue '{parts[1]}' in {count} report(s).")

    except Exception as e:
        log_llm.exception("Error generating historical summary.")
        summary_lines.append(f"[Error generating historical summary: {e}]")

    return "\n".join(summary_lines)


def _create_llm_prompt(report: SystemReport, historical_summary: str) -> str:
    """Constructs the prompt for the LLM based on the report and history."""
    # (Prompt structure remains the same)
    log_llm.debug("Creating LLM prompt...")
    prompt_parts = []
    prompt_parts.append("/no_think")
    prompt_parts.append("""**Role:** You are a System Diagnostics Analyzer AI.

**Task:** Analyze the provided `sysdiag` analyzer report text STRICTLY based on the data presented. Your goal is to identify clear indicators of problems or significant performance bottlenecks.

**Input:** A text block containing the output of the `sysdiag` analyzer tool.

**Instructions:**

1.  **Identify Critical Issues First:**
    * Check "Service Health Analysis Summary": Report any units explicitly mentioned as failed, flapping, or problematic.
    * Check "Dependency Analysis for Failed Units": Report any details found here.
    * Check "Log Analysis": Report any specific OOM errors, critical error patterns, or significant warning patterns explicitly mentioned.

2.  **Analyze Boot Performance:**
    * Examine the "Boot Analysis" -> "Critical Chain": Identify and list the top 1-3 services showing the largest delays (specifically look for values marked with `[red]`, `[bold red]`, or large `+...s`/`+...ms` values). Mention the service name and the delay time.
    * Note the "Total" boot time. Only flag it if it seems exceptionally high (e.g., over 90 seconds) or if specific stages (Firmware, Loader, Kernel, Userspace) are disproportionately long.

3.  **Analyze Resource Usage:**
    * Note the overall Memory and Swap usage percentages. Flag swap usage if it's > 0% as potentially impacting performance. Flag memory usage only if it's consistently very high (e.g., > 90%).
    * Identify the top 1-2 *specific* services/units (NOT slices like `user.slice` or `system.slice` unless they are the *only* high consumers) from the "Top CPU Consumers" and "Top Memory Consumers" tables *only if* their consumption seems excessive for their function (e.g., a background service using many GB of RAM, or extremely high *cumulative* CPU time that doesn't correspond to expected workload like `ollama` or user sessions). Use the "Child Process Group Usage" table to identify application-level memory hogs (like `firefox`, `electron`) but report them simply as "High memory usage noted for [process name]".

4.  **Note Analysis Tool Issues:**
    * Check the "eBPF Process Tracing" section. Report any errors mentioned (like libraries not being installed).

5.  **Interpret ML Anomalies Cautiously:**
    * List the top 2-3 units with the lowest "Anomaly Score" from the "ML Anomaly Detection Analysis".
    * **Crucially:** State that these are *deviations from baseline* and may not represent actual problems unless corroborated by other findings (e.g., if an anomalous unit also appeared in the critical chain delays or high resource usage). Do *not* definitively label them as "problems" based solely on the anomaly score.

6.  **Output Format:**
    * Provide a concise, bulleted list summarizing ONLY the findings based on the rules above.
    * Start with the most critical findings (failed services, major boot delays).
    * If NO significant issues are found according to these strict criteria, state: "No significant issues detected based on the provided report sections."
    * Do NOT add recommendations or explanations beyond what is strictly instructed.
    * Do NOT speculate or infer information not present.

**Input Diagnostic Data:**
""")
    prompt_parts.append("\n### System Overview:")
    prompt_parts.append(f"- Hostname: {report.hostname or 'N/A'}")
    prompt_parts.append(f"- Timestamp: {report.timestamp or 'N/A'}")
    prompt_parts.append(f"- Boot ID: {report.boot_id or 'N/A'}")
    if report.boot_analysis:
        prompt_parts.append("\n### Boot Analysis Summary:")
        if report.boot_analysis.times and report.boot_analysis.times.total: prompt_parts.append(f"- Total Boot Time: {report.boot_analysis.times.total}")
        if report.boot_analysis.blame_error: prompt_parts.append(f"- Blame Error: {report.boot_analysis.blame_error}")
        if report.boot_analysis.critical_chain_error: prompt_parts.append(f"- Critical Chain Error: {report.boot_analysis.critical_chain_error}")
        if report.boot_analysis.critical_chain: prompt_parts.append(f"- Critical Chain: {len(report.boot_analysis.critical_chain)} units identified.")
    if report.health_analysis:
        prompt_parts.append("\n### Health Analysis Summary:")
        ha = report.health_analysis
        issues = []
        if ha.failed_units: issues.append(f"{len(ha.failed_units)} failed units ({', '.join([u.name for u in ha.failed_units[:3]])}{'...' if len(ha.failed_units) > 3 else ''})")
        if ha.flapping_units: issues.append(f"{len(ha.flapping_units)} flapping units ({', '.join([u.name for u in ha.flapping_units[:3]])}{'...' if len(ha.flapping_units) > 3 else ''})")
        if ha.problematic_sockets: issues.append(f"{len(ha.problematic_sockets)} problematic sockets")
        if ha.problematic_timers: issues.append(f"{len(ha.problematic_timers)} problematic timers")
        if issues: prompt_parts.append(f"- Issues Found: {'; '.join(issues)}")
        else: prompt_parts.append("- No major health issues detected.")
        if ha.analysis_error: prompt_parts.append(f"- Analysis Error: {ha.analysis_error}")
    if report.resource_analysis:
        prompt_parts.append("\n### Resource Analysis Summary:")
        ra = report.resource_analysis
        if ra.system_usage:
            sys_usage_parts = []
            if ra.system_usage.cpu_percent is not None: sys_usage_parts.append(f"CPU {ra.system_usage.cpu_percent:.1f}%")
            if ra.system_usage.mem_percent is not None: sys_usage_parts.append(f"Mem {ra.system_usage.mem_percent:.1f}%")
            if ra.system_usage.swap_percent is not None: sys_usage_parts.append(f"Swap {ra.system_usage.swap_percent:.1f}%")
            if sys_usage_parts: prompt_parts.append(f"- System Usage: {', '.join(sys_usage_parts)}")
            if ra.system_usage.error: prompt_parts.append(f"- System Usage Error: {ra.system_usage.error}")
        if ra.top_cpu_units: prompt_parts.append(f"- Top CPU: {ra.top_cpu_units[0].name} ({ra.top_cpu_units[0].cpu_usage_nsec / 1e9:.1f}s){', ...' if len(ra.top_cpu_units) > 1 else ''}")
        if ra.top_memory_units: prompt_parts.append(f"- Top Memory: {ra.top_memory_units[0].name} ({ra.top_memory_units[0].memory_current_bytes / 1024**2:.1f}MiB){', ...' if len(ra.top_memory_units) > 1 else ''}")
        if ra.top_io_units:
            top_io_total = (ra.top_io_units[0].io_read_bytes or 0) + (ra.top_io_units[0].io_write_bytes or 0)
            prompt_parts.append(f"- Top I/O: {ra.top_io_units[0].name} ({top_io_total / 1024**2:.1f}MiB){', ...' if len(ra.top_io_units) > 1 else ''}")
        if ra.analysis_error: prompt_parts.append(f"- Analysis Error: {ra.analysis_error}")
    if report.log_analysis:
        prompt_parts.append("\n### Log Analysis Summary:")
        la = report.log_analysis
        patterns = []
        oom_count = 0
        for p in la.detected_patterns:
            if p.pattern_type == "OOM": oom_count += p.count
            else: patterns.append(f"{p.pattern_key} ({p.count})")
        if oom_count > 0: prompt_parts.append(f"- OOM Events: {oom_count}")
        if patterns: prompt_parts.append(f"- Detected Patterns: {', '.join(patterns[:5])}{'...' if len(patterns) > 5 else ''}")
        if not patterns and oom_count == 0: prompt_parts.append("- No significant error/warning patterns detected.")
        if la.analysis_error: prompt_parts.append(f"- Analysis Error: {la.analysis_error}")
    if report.dependency_analysis and report.dependency_analysis.failed_unit_dependencies:
        prompt_parts.append("\n### Dependency Analysis Summary (Failed Units):")
        da = report.dependency_analysis
        for unit_dep_info in da.failed_unit_dependencies[:3]:
            problematic_deps = [d.name for d in unit_dep_info.dependencies if d.is_problematic]
            if problematic_deps: prompt_parts.append(f"- {unit_dep_info.unit_name}: Problematic dependencies -> {', '.join(problematic_deps)}")
        if len(da.failed_unit_dependencies) > 3: prompt_parts.append("- ... (more units)")
        if da.analysis_error: prompt_parts.append(f"- Analysis Error: {da.analysis_error}")
    if report.full_dependency_analysis and report.full_dependency_analysis.detected_cycles:
         prompt_parts.append("\n### Full Dependency Graph Summary:")
         fda = report.full_dependency_analysis
         prompt_parts.append(f"- Detected {len(fda.detected_cycles)} dependency cycle(s).")
         if fda.analysis_error: prompt_parts.append(f"- Analysis Error: {fda.analysis_error}")
    if report.ml_analysis: # Check if ml_analysis exists first
        prompt_parts.append("\n### ML Anomaly Detection Summary:")
        mla = report.ml_analysis
        if mla.anomalies_detected:
             anomalies_summary = [f"{a.unit_name} (Score: {a.score:.2f})" for a in mla.anomalies_detected[:3]]
             prompt_parts.append(f"- Detected Anomalies: {', '.join(anomalies_summary)}{'...' if len(mla.anomalies_detected) > 3 else ''}")
        else:
             prompt_parts.append("- No anomalies detected.")
        # FIX: Use correct attribute name 'error' instead of 'analysis_error'
        if mla.error: prompt_parts.append(f"- Analysis Error: {mla.error}")
    prompt_parts.append("\n### Historical Context Summary:")
    prompt_parts.append(historical_summary if historical_summary else "No historical summary generated.")
    prompt_parts.append("---")
    prompt_parts.append("## Task:")
    prompt_parts.append("Provide a concise synthesis of the system's health based *only* on the data above. Structure your response in Markdown.")
    prompt_parts.append("1.  **Overall Summary:** Briefly state the main findings (e.g., 'System shows 2 failed units and high memory usage by unit X.').")
    prompt_parts.append("2.  **Issue Breakdown & Correlation:** For each major issue (failed units, anomalies, critical performance bottlenecks, OOMs), discuss potential causes by correlating data from different sections. Highlight relevant historical context.")
    prompt_parts.append("3.  **Recommendations:** For each major issue, suggest 1-3 specific, actionable troubleshooting steps based *directly* on the analysis findings (e.g., 'Check logs for unit Y', 'Increase memory limit for unit Z', 'Investigate dependency cycle A->B->A', 'Compare current resource usage of unit P against historical norms').")
    prompt_parts.append("Keep the analysis factual and directly tied to the provided report data.")
    final_prompt = "\n".join(prompt_parts)
    log_llm.debug(f"Generated LLM Prompt (length: {len(final_prompt)}):\n---\n{final_prompt[:1000]}...\n---")
    return final_prompt


# --- Main Orchestration Function ---

def analyze_with_llm(
    report: SystemReport,
    llm_config: Dict[str, Any],
    history_dir: Path
) -> LLMAnalysisResult:
    """
    Orchestrates the LLM analysis using the configured provider.
    """
    result = LLMAnalysisResult()
    log_llm.info("Starting LLM analysis orchestration...")

    provider_name = llm_config.get("provider")
    model_name = llm_config.get("model")

    if not provider_name:
        result.error = "LLM provider not specified in configuration ([llm] -> provider)."
        log_llm.error(result.error)
        return result
    if not model_name:
        result.error = f"LLM model not specified in configuration ([llm] -> model) for provider '{provider_name}'."
        log_llm.error(result.error)
        return result

    result.provider_used = provider_name
    result.model_used = model_name

    provider = LLMProvider.get_provider(provider_name, model_name, llm_config)
    if provider is None:
        result.error = f"Failed to initialize LLM provider '{provider_name}'."
        return result

    try:
        historical_summary = _generate_historical_summary(report, history_dir)
        prompt = _create_llm_prompt(report, historical_summary)

        temperature = float(llm_config.get("temperature", DEFAULT_LLM_TEMPERATURE))
        max_tokens = int(llm_config.get("max_tokens", DEFAULT_LLM_MAX_TOKENS))
        context_window = int(llm_config.get("context_window", DEFAULT_LLM_CONTEXT_WINDOW))

        synthesis, token_usage, error = provider.generate(prompt, temperature, max_tokens, context_window)

        if error:
            result.error = f"LLM generation failed: {error}"
            log_llm.error(result.error)
        else:
            result.synthesis = synthesis
            if token_usage:
                result.prompt_token_count = token_usage.get("prompt_tokens")
                result.completion_token_count = token_usage.get("completion_tokens")
            log_llm.info("LLM synthesis generated successfully.")

    except Exception as e:
        log_llm.exception("Unexpected error during LLM analysis orchestration.")
        result.error = f"Unexpected LLM analysis error: {e}"

    return result
