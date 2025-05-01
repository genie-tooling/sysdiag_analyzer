# -*- coding: utf-8 -*-

import logging
import os
import sys
import platform
import datetime
import json
import gzip
import pathlib
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple # Added Tuple

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel # Import Panel for config show
from rich.syntax import Syntax # Import Syntax for config show
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass

# --- Local Imports ---
from .datatypes import (
    SystemReport,
    BootAnalysisResult,
    HealthAnalysisResult,
    ResourceAnalysisResult,
    LogAnalysisResult,
    DependencyAnalysisResult,
    FullDependencyAnalysisResult,
    MLAnalysisResult,
    LLMAnalysisResult,
    EBPFAnalysisResult, # Added Phase 10
    AnomalyInfo,
    BootTimes,
    UnitHealthInfo # Added UnitHealthInfo
)
from .modules.boot import analyze_boot as analyze_boot_logic
from .modules.health import (
    analyze_health as analyze_health_logic,
    _get_systemd_manager_interface,
    _get_all_units_dbus,
    _get_all_units_json
)
from .modules.resources import analyze_resources as analyze_resources_logic
from .modules.logs import (
    analyze_general_logs as analyze_logs_logic,
    DEFAULT_ANALYSIS_LEVEL
)
from .modules.dependencies import (
    analyze_dependencies as analyze_dependencies_logic,
    analyze_full_dependency_graph
)
# Import ML Engine
try:
    from . import ml_engine
    HAS_ML_ENGINE = ml_engine.HAS_ML_LIBS
except ImportError:
    ml_engine = None # type: ignore
    HAS_ML_ENGINE = False

# Import LLM Analyzer
try:
    from . import llm_analyzer
    HAS_LLM_OLLAMA = llm_analyzer.HAS_OLLAMA
    HAS_LLM_ENGINE = True
except ImportError:
    llm_analyzer = None # type: ignore
    HAS_LLM_ENGINE = False
    HAS_LLM_OLLAMA = False

# Import eBPF Monitor (Phase 10)
HAS_BCC = False
HAS_EBPF_MONITOR = False
try:
    from .modules import ebpf_monitor
    HAS_EBPF_MONITOR = True
    HAS_BCC = ebpf_monitor.HAS_BCC
    # REMOVED DEBUG PRINT
except ImportError as e:
    log_ebpf_import = logging.getLogger(__name__)
    log_ebpf_import.warning(f"Could not import ebpf_monitor module: {e}. eBPF features disabled.", exc_info=False)
    ebpf_monitor = None # type: ignore
    HAS_EBPF_MONITOR = False
    HAS_BCC = False


from .output import (
    format_rich_report,
    format_json_report,
    format_boot_report,
    format_health_report,
    format_resource_report,
    format_log_report,
    format_dependency_report,
    format_full_dependency_report,
    format_ml_report,
    format_llm_report,
    format_ebpf_report # Added Phase 10
)
from .utils import run_subprocess, get_boot_id
from .features import extract_features_from_report # Used by ML/LLM
from .config import load_config, DEFAULT_CONFIG # Import config loading

# --- Basic Configuration ---
LOG_LEVEL = logging.INFO
CONSOLE = Console(stderr=True)

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=CONSOLE, rich_tracebacks=True, show_path=False)]
)
log = logging.getLogger(__name__)

app = typer.Typer(
    help="Sysdiag-Analyzer: Systemd & System Health Diagnostic Tool with ML, LLM & eBPF."
)

# --- Helper Functions ---
def check_privileges(required_for: str = "some checks") -> bool: # Added return type hint
    """Warns if not running as root, as many checks require it."""
    is_root = False
    try:
        if os.geteuid() == 0:
            is_root = True
        else:
            log.warning(
                f"Running without root privileges. Required for {required_for}. "
                "Some checks may fail or be incomplete."
            )
    except AttributeError:
        log.warning("Could not determine user privileges (non-POSIX?). Assuming non-root.")
    return is_root


# --- Persistence Logic (_save_report, _apply_retention) ---
def _save_report(report: SystemReport, history_dir: Path):
    """Saves the report to the history directory."""
    log.info("Attempting to save analysis report...")
    boot_id = report.boot_id or get_boot_id() or "unknown_boot"
    timestamp_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = history_dir / f"report-{boot_id}-{timestamp_str}.jsonl.gz"

    try:
        history_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    except PermissionError:
        log.error(f"Permission denied creating history directory: {history_dir}")
        report.errors.append("Failed to save report: Cannot create history directory.")
        return
    except Exception as e:
        log.error(f"Error creating history directory {history_dir}: {e}")
        report.errors.append(f"Failed to save report: Error creating history directory: {e}")
        return

    try:
        report_dict = asdict(report)
        report_json = json.dumps(report_dict, default=str)

        with gzip.open(filename, "wt", encoding="utf-8") as f:
            f.write(report_json + "\n")
        log.info(f"Successfully saved report to {filename}")
    except TypeError as e:
         log.error(f"Failed to serialize report to JSON: {e}", exc_info=True)
         report.errors.append(f"Failed to save report: JSON serialization error: {e}")
    except (IOError, OSError, gzip.BadGzipFile) as e:
         log.error(f"Failed to write compressed report to {filename}: {e}", exc_info=True)
         report.errors.append(f"Failed to save report: File write error: {e}")
    except Exception as e:
         log.error(f"Unexpected error saving report {filename}: {e}", exc_info=True)
         report.errors.append(f"Failed to save report: Unexpected error: {e}")


def _apply_retention(history_dir: Path, max_files: int):
    """Applies the retention policy to the history directory."""
    log.info(f"Applying retention policy (max {max_files} files) in {history_dir}...")
    try:
        history_files = sorted(
            history_dir.glob("report-*.jsonl.gz"),
            key=os.path.getmtime
        )
        files_to_delete_count = len(history_files) - max_files
        if files_to_delete_count > 0:
            log.info(f"Found {len(history_files)} reports, keeping {max_files}, deleting {files_to_delete_count}.")
            for i in range(files_to_delete_count):
                file_to_delete = history_files[i]
                try:
                    log.debug(f"Deleting old report: {file_to_delete}")
                    file_to_delete.unlink()
                except FileNotFoundError:
                    log.warning(f"File not found during deletion (likely race condition): {file_to_delete}")
                except (OSError, PermissionError) as delete_e:
                    log.error(f"Failed to delete old report {file_to_delete}: {delete_e}")
        else:
            log.debug("No old reports need deletion.")
    except Exception as e:
        log.error(f"Error applying retention policy in {history_dir}: {e}", exc_info=True)


# --- Core Analysis Function ---
def run_full_analysis(
    history_dir: Path,
    model_dir: Path,
    all_units: List[UnitHealthInfo], # Added parameter
    dbus_manager: Optional[Any],    # Added parameter
    since: Optional[str] = None,
    enable_ebpf: bool = False,
    analyze_full_graph: bool = False,
    analyze_ml: bool = False,
    analyze_llm: bool = False,
    llm_config: Optional[Dict[str, Any]] = None,
) -> SystemReport:
    """Gathers all analysis data."""
    log.info("Starting full system analysis (inside run_full_analysis)...")
    # Check privileges again inside analysis for completeness, but primary check is in run()
    is_root = check_privileges(required_for="eBPF tracing, cgroup access, DBus, journal")

    current_boot_id = get_boot_id()
    report = SystemReport(
        hostname=platform.node(),
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        boot_id=current_boot_id
    )

    # --- DBus manager and unit list are now passed in ---
    if not all_units:
        log.warning("run_full_analysis received empty unit list. Analysis will be limited.")
        # Add an error? Or just proceed? Let's proceed but results will be empty.
        report.errors.append("Analysis performed with empty unit list.")

    # --- eBPF Setup (if enabled) ---
    ebpf_collector = None
    if enable_ebpf:
        if not is_root:
            log.error("eBPF analysis requested, but not running as root. Skipping eBPF.")
            report.errors.append("eBPF analysis skipped: Root privileges required.")
            report.ebpf_analysis = EBPFAnalysisResult(error="Root privileges required.")
        elif not HAS_EBPF_MONITOR or not ebpf_monitor:
            log.error("eBPF analysis requested, but eBPF module failed to load.")
            report.errors.append("eBPF analysis skipped: Module load failed.")
            report.ebpf_analysis = EBPFAnalysisResult(error="eBPF module load failed.")
        elif not HAS_BCC:
            log.error("eBPF analysis requested, but 'bcc' library is not installed.")
            report.errors.append("eBPF analysis skipped: 'bcc' library missing (install sysdiag-analyzer[ebpf]).")
            report.ebpf_analysis = EBPFAnalysisResult(error="'bcc' library not installed.")
        else:
            try:
                log.info("Initializing eBPF monitoring...")
                ebpf_collector = ebpf_monitor.EBPFCollector()
                ebpf_collector.start()
                log.info("eBPF monitoring started.")
            except Exception as e:
                log.exception("Failed to initialize or start eBPF monitoring.")
                report.errors.append(f"eBPF initialization failed: {e}")
                report.ebpf_analysis = EBPFAnalysisResult(error=f"Initialization failed: {e}")
                ebpf_collector = None # Ensure collector is None if start failed
    else:
        log.info("Skipping eBPF analysis (flag not set).")

    # --- Run Core Analyses Sequentially ---
    # Boot analysis
    try:
        report.boot_analysis = analyze_boot_logic()
    except Exception as e:
        log.exception("Error during boot analysis.")
        report.errors.append(f"Boot analysis failed: {e}")
        if report.boot_analysis is None:
            report.boot_analysis = BootAnalysisResult()
        if report.boot_analysis.times is None:
            report.boot_analysis.times = BootTimes()
        report.boot_analysis.times.error = report.boot_analysis.times.error or f"Failed to get result: {e}"

    # Health analysis - Pass the fetched list
    try:
        # Use the passed-in units list and manager
        report.health_analysis = analyze_health_logic(
            units=all_units,
            dbus_manager=dbus_manager
        )
    except Exception as e:
        log.exception("Error during health analysis.")
        report.errors.append(f"Health analysis failed: {e}")
        if report.health_analysis is None:
            report.health_analysis = HealthAnalysisResult(analysis_error=f"Failed to get result: {e}")
        else:
            report.health_analysis.analysis_error = report.health_analysis.analysis_error or f"Failed to get result: {e}"

    # Resource analysis - Pass the fetched list
    try:
        # Use the passed-in units list and manager
        report.resource_analysis = analyze_resources_logic(
            units=all_units,
            dbus_manager=dbus_manager
        )
    except Exception as e:
        log.exception("Error during resource analysis.")
        report.errors.append(f"Resource analysis failed: {e}")
        if report.resource_analysis is None:
            report.resource_analysis = ResourceAnalysisResult(analysis_error=f"Failed to get result: {e}")
        else:
            report.resource_analysis.analysis_error = report.resource_analysis.analysis_error or f"Failed to get result: {e}"

    # Dependency analysis (Failed Units)
    try:
        # Use the detailed failed units list directly from health analysis result
        failed_units_to_analyze = report.health_analysis.failed_units if report.health_analysis else []
        if failed_units_to_analyze:
            log.info(f"Running dependency analysis for {len(failed_units_to_analyze)} failed units...")
            # Use the passed-in manager
            report.dependency_analysis = analyze_dependencies_logic(
                failed_units=failed_units_to_analyze,
                dbus_manager=dbus_manager
            )
        else:
            log.info("Skipping dependency analysis: No failed units identified.")
            report.dependency_analysis = DependencyAnalysisResult()
    except Exception as e:
        log.exception("Error during dependency analysis.")
        report.errors.append(f"Dependency analysis failed: {e}")
        if report.dependency_analysis is None:
            report.dependency_analysis = DependencyAnalysisResult(analysis_error=f"Failed to get result: {e}")
        else:
            report.dependency_analysis.analysis_error = report.dependency_analysis.analysis_error or f"Failed to get result: {e}"

    # Full Dependency Graph Analysis (Optional)
    if analyze_full_graph:
        log.info("Full dependency graph analysis requested.")
        try:
            report.full_dependency_analysis = analyze_full_dependency_graph()
            if report.full_dependency_analysis and report.full_dependency_analysis.analysis_error:
                 report.errors.append(f"Full Graph Analysis: {report.full_dependency_analysis.analysis_error}")
        except Exception as e:
            log.exception("Error during full dependency graph analysis.")
            err_msg = f"Full dependency graph analysis failed: {e}"
            report.errors.append(err_msg)
            if report.full_dependency_analysis is None:
                report.full_dependency_analysis = FullDependencyAnalysisResult(analysis_error=err_msg)
            report.full_dependency_analysis.analysis_error = err_msg
    else:
         log.info("Skipping full dependency graph analysis (flag not set).")

    # Log analysis
    try:
        report.log_analysis = analyze_logs_logic()
    except Exception as e:
        log.exception("Error during log analysis.")
        report.errors.append(f"Log analysis failed: {e}")
        if report.log_analysis is None:
            report.log_analysis = LogAnalysisResult(analysis_error=f"Failed to get result: {e}")
        else:
            report.log_analysis.analysis_error = report.log_analysis.analysis_error or f"Failed to get result: {e}"

    # eBPF Teardown & Data Collection
    if ebpf_collector:
        log.info("Stopping eBPF monitoring and collecting events...")
        try:
            report.ebpf_analysis = ebpf_collector.stop()
            log.info(f"Collected {len(report.ebpf_analysis.exec_events)} exec events and {len(report.ebpf_analysis.exit_events)} exit events.")
            # TODO: Add correlation logic here to map cgroup IDs to unit names
        except Exception as e:
            log.exception("Error stopping eBPF monitoring or collecting data.")
            err_msg = f"eBPF data collection failed: {e}"
            report.errors.append(err_msg)
            if report.ebpf_analysis is None:
                report.ebpf_analysis = EBPFAnalysisResult()
            report.ebpf_analysis.error = err_msg

    # ML Analysis (Optional)
    if analyze_ml:
        log.info("ML analysis requested.")
        ml_result = MLAnalysisResult()
        report.ml_analysis = ml_result

        if not HAS_ML_ENGINE or not ml_engine:
            ml_result.error = "ML dependencies (pandas, scikit-learn, joblib) not installed. Skipping ML analysis."
            log.error(ml_result.error)
        else:
            try:
                current_report_dict = asdict(report)
                current_features_list = extract_features_from_report(current_report_dict)

                if not current_features_list:
                    ml_result.error = "No features could be extracted from the current report for ML analysis."
                    log.warning(ml_result.error)
                else:
                    current_features_df = ml_engine.pd.DataFrame(current_features_list)
                    current_features_engineered_df = ml_engine.engineer_features(current_features_df)

                    if current_features_engineered_df is None or current_features_engineered_df.empty:
                         ml_result.error = "Feature engineering failed or resulted in empty data for current report."
                         log.warning(ml_result.error)
                    else:
                        log.info("Loading pre-trained ML models...")
                        anomaly_models = ml_engine.load_models(ml_engine.ANOMALY_MODEL_TYPE, model_dir)
                        scalers = ml_engine.load_models(ml_engine.SCALER_MODEL_TYPE, model_dir)
                        ml_result.models_loaded_count = len(anomaly_models)

                        if not anomaly_models or not scalers:
                            ml_result.error = f"No pre-trained anomaly models or scalers found in {model_dir}. Run 'retrain-ml' first."
                            log.warning(ml_result.error)
                        else:
                            log.info("Detecting anomalies using loaded models...")
                            if 'report_timestamp' in current_features_engineered_df.columns:
                                if 'unit_name' in current_features_engineered_df.columns:
                                    latest_features_df = current_features_engineered_df.loc[
                                        current_features_engineered_df.groupby('unit_name')['report_timestamp'].idxmax()
                                    ]
                                    ml_result.anomalies_detected = ml_engine.detect_anomalies(latest_features_df, anomaly_models, scalers)
                                    ml_result.units_analyzed_count = len(latest_features_df)
                                    log.info(f"ML analysis complete. Detected {len(ml_result.anomalies_detected)} anomalies in {ml_result.units_analyzed_count} units.")
                                else:
                                    ml_result.error = "Engineered features DataFrame missing 'unit_name' column."
                                    log.error(ml_result.error)
                            else:
                                ml_result.error = "Engineered features DataFrame missing 'report_timestamp' column."
                                log.error(ml_result.error)

            except ImportError as imp_err:
                 ml_result.error = f"ML analysis failed due to missing dependency: {imp_err}"
                 log.error(ml_result.error)
            except Exception as e:
                log.exception("Error during ML analysis.")
                ml_result.error = f"ML analysis failed: {e}"
                report.errors.append(ml_result.error)
    else:
        log.info("Skipping ML analysis (flag not set).")

    # LLM Synthesis (Optional)
    if analyze_llm:
        log.info("LLM synthesis requested.")
        llm_result = LLMAnalysisResult()
        report.llm_analysis = llm_result

        if not llm_config:
             llm_result.error = "LLM analysis requested, but LLM configuration was not provided."
             log.error(llm_result.error)
        elif not HAS_LLM_ENGINE or not llm_analyzer:
             llm_result.error = "LLM analysis module failed to load internally."
             log.error(llm_result.error)
        else:
            try:
                provider_name = llm_config.get("provider")
                model_name = llm_config.get("model")
                log.info(f"Running LLM synthesis using provider '{provider_name}' and model '{model_name}'...")
                report.llm_analysis = llm_analyzer.analyze_with_llm(
                    report=report,
                    llm_config=llm_config,
                    history_dir=history_dir
                )
                log.info("LLM synthesis finished.")
                if report.llm_analysis and report.llm_analysis.error:
                     log.error(f"LLM Analysis Error: {report.llm_analysis.error}")

            except Exception as e:
                log.exception("Error during LLM analysis orchestration.")
                err_msg = f"LLM synthesis failed: {e}"
                if report.llm_analysis is None:
                    report.llm_analysis = LLMAnalysisResult()
                report.llm_analysis.error = err_msg
                report.errors.append(err_msg)
    else:
        log.info("Skipping LLM synthesis (flag not set).")

    log.info("Full system analysis finished (within run_full_analysis).")
    return report


# --- Typer Commands ---
config_app = typer.Typer(help="Manage sysdiag-analyzer configuration.")
app.add_typer(config_app, name="config")

@config_app.command("show")
def config_show(
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to a specific TOML configuration file to load.", exists=False, file_okay=True, dir_okay=False, readable=True),
):
    """Display the currently loaded configuration (merged from defaults and files)."""
    try:
        loaded_conf = load_config(config_path_override=config_file)
        conf_json = json.dumps(loaded_conf, indent=2, default=str)
        syntax = Syntax(conf_json, "json", theme="default", line_numbers=True)
        CONSOLE.print(Panel(syntax, title="Loaded Configuration", border_style="blue"))
    except Exception as e:
        log.exception("Failed to load or display configuration.")
        CONSOLE.print(f"[bold red]Error:[/bold red] Failed to load or display configuration: {e}")
        raise typer.Exit(code=1)


@app.command()
def run(
    since: Optional[str] = typer.Option(None, "--since", help="Analyze logs since this time (e.g., '1 hour ago', 'yesterday') - Not Implemented Yet."),
    output: str = typer.Option("rich", "--output", "-o", help="Output format ('rich' or 'json')."),
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to a custom TOML configuration file.", exists=False, file_okay=True, dir_okay=False, readable=True),
    enable_ebpf: bool = typer.Option(False, "--enable-ebpf", help="Enable eBPF-based process tracing (requires root and bcc)."),
    analyze_full_graph: bool = typer.Option(False, "--analyze-full-graph", help="Perform full dependency graph analysis to detect cycles (requires networkx)."),
    analyze_ml: bool = typer.Option(False, "--analyze-ml", help="Perform ML-based anomaly detection (requires trained models)."),
    analyze_llm: bool = typer.Option(False, "--analyze-llm", help="Perform LLM-based synthesis of the report (requires configuration and Ollama)."),
    llm_model: Optional[str] = typer.Option(None, "--llm-model", help="Override the LLM model specified in the config file."),
    no_save: bool = typer.Option(False, "--no-save", help="Do not save the analysis report to the history directory."),
):
    """
    Run a full system health analysis (Boot, Services, Resources, Logs, Dependencies).
    Optionally includes full dependency graph cycle detection, ML anomaly detection,
    LLM-based synthesis, and eBPF process tracing. Saves report by default.
    """
    report: Optional[SystemReport] = None
    try:
        # --- Load Config ---
        app_config = load_config(config_path_override=config_file)
        current_history_dir = Path(app_config.get("history", {}).get("directory", DEFAULT_CONFIG["history"]["directory"]))
        current_max_history = app_config.get("history", {}).get("max_files", DEFAULT_CONFIG["history"]["max_files"])
        current_model_dir = Path(app_config.get("models", {}).get("directory", DEFAULT_CONFIG["models"]["directory"]))

        # --- LLM Fail-Fast Validation ---
        effective_llm_config = None
        if analyze_llm:
            log.debug("Performing pre-analysis LLM configuration checks...")
            llm_config_section = app_config.get("llm", {})
            provider_name = llm_config_section.get("provider")
            effective_model_name = llm_model or llm_config_section.get("model")
            if not HAS_LLM_ENGINE:
                CONSOLE.print("[bold red]Error:[/bold red] LLM analysis requested, but LLM dependencies are not installed.")
                CONSOLE.print("Install with: [cyan]pip install sysdiag-analyzer[llm][/cyan]")
                raise typer.Exit(code=1)
            if not provider_name:
                # FIX: Use string concatenation/formatting
                CONSOLE.print("[bold red]Error:[/bold red] LLM analysis requested, but 'provider' is not specified in the [llm] section of the configuration file.")
                raise typer.Exit(code=1)
            if not effective_model_name:
                # FIX: Use string concatenation/formatting
                CONSOLE.print("[bold red]Error:[/bold red] LLM analysis requested, but 'model' is not specified in the [llm] section of the configuration file and not provided via --llm-model.")
                raise typer.Exit(code=1)
            if provider_name == "ollama" and not HAS_LLM_OLLAMA:
                CONSOLE.print("[bold red]Error:[/bold red] LLM provider 'ollama' configured, but the 'ollama' library is not installed.")
                CONSOLE.print("Install with: [cyan]pip install sysdiag-analyzer[llm][/cyan]")
                raise typer.Exit(code=1)
            effective_llm_config = llm_config_section.copy()
            effective_llm_config["model"] = effective_model_name
            log.debug("LLM pre-analysis configuration checks passed.")

        # --- Connect to DBus Once ---
        dbus_manager = _get_systemd_manager_interface()

        # --- Fetch Unit List Once ---
        all_units: List[UnitHealthInfo] = []
        fetch_error: Optional[str] = None
        log.info("Fetching unit list...")
        if dbus_manager:
            all_units, fetch_error = _get_all_units_dbus(dbus_manager)
            if fetch_error or not all_units:
                log.warning(f"DBus ListUnits failed or returned empty ({fetch_error}), attempting systemctl fallback...")
                all_units, fetch_error = _get_all_units_json()
        else:
            log.info("DBus manager not available or DBus not installed, using systemctl fallback for unit list.")
            all_units, fetch_error = _get_all_units_json()

        if fetch_error:
            if not all_units:
                log.error(f"Failed to get unit list: {fetch_error}")
                CONSOLE.print(f"[bold red]Error:[/bold red] Failed to retrieve unit list ({fetch_error}). Analysis cannot proceed.")
                raise typer.Exit(code=1)
            else:
                log.warning(f"Initial unit fetch failed ({fetch_error}), but fallback succeeded.")
        elif not all_units:
            log.warning("No units found for analysis.")
            CONSOLE.print("[yellow]Warning:[/yellow] No systemd units found. Analysis may be incomplete.")
            # Allow continuing, but the report will be mostly empty

        # --- Run Analysis ---
        report = run_full_analysis(
            history_dir=current_history_dir,
            model_dir=current_model_dir,
            all_units=all_units,         # Pass fetched units
            dbus_manager=dbus_manager,   # Pass manager object
            since=since,
            enable_ebpf=enable_ebpf,
            analyze_full_graph=analyze_full_graph,
            analyze_ml=analyze_ml,
            analyze_llm=analyze_llm,
            llm_config=effective_llm_config,
        )

        # --- Persistence ---
        if not no_save:
            if report:
                _save_report(report, current_history_dir)
                _apply_retention(current_history_dir, current_max_history)
            else:
                log.error("Analysis failed to produce a report, cannot save.")
        else:
            log.info("Skipping report saving as per --no-save flag.")

        # --- Output ---
        if output == "rich":
            format_rich_report(report, CONSOLE)
        elif output == "json":
            print(format_json_report(report))
        else:
            log.error(f"Unsupported output format: {output}")
            raise typer.Exit(code=1)

        # --- Exit Code ---
        exit_code = 0
        if report:
            if report.health_analysis and report.health_analysis.failed_units:
                exit_code = 1
            elif report.ml_analysis and report.ml_analysis.anomalies_detected:
                exit_code = 1
            elif report.llm_analysis and report.llm_analysis.error:
                exit_code = 1
            elif report.ebpf_analysis and report.ebpf_analysis.error:
                exit_code = 1
            elif report.errors:
                exit_code = 1
        else:
             exit_code = 1

        if exit_code != 0:
             log.warning(f"Exiting with code {exit_code} due to detected issues or errors.")
             raise typer.Exit(code=exit_code)

    except typer.Exit:
        raise
    except Exception as e:
        log.exception(f"An unexpected error occurred during command 'run': {e}")
        if not isinstance(e, typer.Exit):
             raise typer.Exit(code=1)


# --- retrain-ml Command ---
@app.command()
def retrain_ml(
    num_reports: int = typer.Option(50, "--num-reports", "-n", help="Number of recent history reports to use for training."),
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to a custom TOML configuration file.", exists=False, file_okay=True, dir_okay=False, readable=True),
):
    """
    Load historical data and retrain the ML anomaly detection models.
    Requires root privileges to save models to the default location.
    """
    # (Logic remains the same)
    log.info("Starting ML model retraining process...")
    check_privileges(required_for="saving models to default location")

    app_config = load_config(config_path_override=config_file)
    current_history_dir = Path(app_config.get("history", {}).get("directory", DEFAULT_CONFIG["history"]["directory"]))
    current_model_dir = Path(app_config.get("models", {}).get("directory", DEFAULT_CONFIG["models"]["directory"]))
    if ml_engine:
        models_cfg = app_config.get("models", {})
        ml_engine.DEFAULT_ISOLATION_FOREST_CONTAMINATION = models_cfg.get("anomaly_contamination", ml_engine.DEFAULT_ISOLATION_FOREST_CONTAMINATION)
        ml_engine.MIN_SAMPLES_FOR_TRAINING = models_cfg.get("min_samples_train", ml_engine.MIN_SAMPLES_FOR_TRAINING)

    if not HAS_ML_ENGINE or not ml_engine:
        CONSOLE.print("[red]Error: ML dependencies (pandas, scikit-learn, joblib) not installed. Cannot retrain.[/red]")
        CONSOLE.print("Install with: pip install sysdiag-analyzer[ml]")
        raise typer.Exit(code=1)

    if not current_model_dir.exists():
        try:
            log.info(f"Attempting to create model directory: {current_model_dir}")
            current_model_dir.mkdir(parents=True, mode=0o700)
        except PermissionError:
             CONSOLE.print(f"[red]Error: Permission denied creating model directory: {current_model_dir}. Run with sudo?[/red]")
             raise typer.Exit(code=1)
        except Exception as e:
             CONSOLE.print(f"[red]Error creating model directory {current_model_dir}: {e}[/red]")
             raise typer.Exit(code=1)

    features_df = ml_engine.load_and_prepare_data(history_dir=current_history_dir, num_reports=num_reports)
    if features_df is None or features_df.empty:
        CONSOLE.print("[yellow]Warning: No data available for training. Ensure history reports exist.[/yellow]")
        raise typer.Exit(code=0)

    try:
        engineered_df = ml_engine.engineer_features(features_df)
        if engineered_df is None or engineered_df.empty:
            CONSOLE.print("[red]Error: Feature engineering failed. Check logs.[/red]")
            raise typer.Exit(code=1)

        CONSOLE.print("Training anomaly detection models (Isolation Forest)...")
        trained_models, trained_scalers, skipped_units = ml_engine.train_anomaly_models(engineered_df, current_model_dir)

        if not trained_models:
             CONSOLE.print("[yellow]Warning: No models were successfully trained (e.g., insufficient data per unit).[/yellow]")
        else:
             CONSOLE.print(f"[green]Successfully trained and saved {len(trained_models)} anomaly models and {len(trained_scalers)} scalers to {current_model_dir}.[/green]")

        if skipped_units:
             CONSOLE.print(f"[dim]Skipped training for {len(skipped_units)} units due to insufficient data or zero variance (see logs for details).[/dim]")

    except PermissionError as e:
         log.error(f"Permission denied during model saving: {e}")
         CONSOLE.print(f"[red]Error: Permission denied saving models to {current_model_dir}. Run with sudo?[/red]")
         raise typer.Exit(code=1)
    except Exception as e:
        log.exception(f"An unexpected error occurred during ML retraining: {e}")
        CONSOLE.print(f"[red]An unexpected error occurred during retraining: {e}[/red]")
        raise typer.Exit(code=1)

    log.info("ML model retraining finished.")

# --- show-history Command ---
@app.command()
def show_history(
    limit: int = typer.Option(5, "--limit", "-n", help="Number of recent reports to show metadata for."),
    output: str = typer.Option("rich", "--output", "-o", help="Output format ('rich' or 'json')."),
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to a custom TOML configuration file.", exists=False, file_okay=True, dir_okay=False, readable=True),
):
    """List metadata about recent analysis reports stored in the history."""
    # (Logic remains the same)
    app_config = load_config(config_path_override=config_file)
    current_history_dir = Path(app_config.get("history", {}).get("directory", DEFAULT_CONFIG["history"]["directory"]))

    log.info(f"Listing metadata for last {limit} reports from {current_history_dir}...")
    if not current_history_dir.is_dir():
        CONSOLE.print(f"[yellow]History directory not found:[/yellow] {current_history_dir}")
        raise typer.Exit(code=1)

    try:
        history_files = sorted(
            current_history_dir.glob("report-*.jsonl.gz"),
            key=os.path.getmtime,
            reverse=True # Newest first
        )

        reports_meta = []
        for i, report_file in enumerate(history_files[:limit]):
             try:
                 stat_result = report_file.stat()
                 meta = {
                     "index": i + 1,
                     "filename": report_file.name,
                     "size_kb": f"{stat_result.st_size / 1024:.1f}",
                     "modified_utc": datetime.datetime.fromtimestamp(
                         stat_result.st_mtime, datetime.timezone.utc
                     ).isoformat()
                 }
                 reports_meta.append(meta)
             except FileNotFoundError:
                  log.warning(f"History file disappeared while listing: {report_file.name}")
             except OSError as stat_e:
                  log.error(f"Could not stat history file {report_file.name}: {stat_e}")


        if not reports_meta:
             CONSOLE.print("[dim]No history reports found.[/dim]")
             return

        if output == "rich":
             from rich.table import Table
             table = Table(title=f"Recent Analysis Reports (Last {len(reports_meta)})", show_header=True, header_style="bold magenta")
             table.add_column("#", style="dim", width=3)
             table.add_column("Filename", style="cyan")
             table.add_column("Size (KiB)", style="green", justify="right")
             table.add_column("Saved Timestamp (UTC)", style="yellow")
             for meta in reports_meta:
                  table.add_row(str(meta["index"]), meta["filename"], meta["size_kb"], meta["modified_utc"])
             CONSOLE.print(table)
        elif output == "json":
             print(json.dumps(reports_meta, indent=2))
        else:
            log.error(f"Unsupported output format: {output}")
            raise typer.Exit(code=1)

    except Exception as e:
        log.exception(f"Error accessing or listing history directory {current_history_dir}: {e}")
        raise typer.Exit(code=1)


# --- analyze_unit Command (Still stubbed) ---
@app.command()
def analyze_unit(
    unit_name: str = typer.Argument(..., help="The name of the systemd unit to analyze (e.g., 'nginx.service')."),
    output: str = typer.Option("rich", "--output", "-o", help="Output format ('rich' or 'json')."),
):
    """Perform a focused analysis on a specific systemd unit (Not Implemented Yet)."""
    check_privileges()
    log.warning(f"Analysis for specific unit '{unit_name}' is not yet implemented.")
    CONSOLE.print(f"Placeholder: Would analyze {unit_name} with output format {output}")

# --- analyze_* specific commands (updated to use fetch logic) ---
@app.command()
def analyze_boot(
    output: str = typer.Option("rich", "--output", "-o", help="Output format ('rich' or 'json')."),
):
    """Analyze the last system boot performance."""
    check_privileges()
    log.info("Starting boot-only analysis...")
    try:
        result = analyze_boot_logic()
        if result:
            if output == "rich":
                format_boot_report(result, CONSOLE)
            elif output == "json":
                print(json.dumps(asdict(result), indent=2, default=str))
            else:
                log.error(f"Unsupported output format: {output}")
                raise typer.Exit(code=1)
        else:
            log.error("Boot analysis failed to produce results.")
            raise typer.Exit(code=1)
    except Exception as e:
        log.exception(f"An unexpected error occurred: {e}")
        raise typer.Exit(code=1)

@app.command()
def analyze_health(
    output: str = typer.Option("rich", "--output", "-o", help="Output format ('rich' or 'json')."),
):
    """Analyze the health of systemd units (failed, flapping, sockets, timers)."""
    check_privileges()
    log.info("Starting health-only analysis...")
    try:
        dbus_manager = _get_systemd_manager_interface()
        # Fetch units first
        units, fetch_error = [], None
        if dbus_manager:
            units, fetch_error = _get_all_units_dbus(dbus_manager)
        if fetch_error or not units:
            units, fetch_error = _get_all_units_json()
        if fetch_error and not units:
            log.error(f"Failed to fetch units: {fetch_error}")
            raise typer.Exit(code=1)
        if not units:
            log.warning("No units found.")
            CONSOLE.print("[yellow]No units found.[/yellow]")
            raise typer.Exit(code=0)

        # Pass fetched units to analysis function
        result = analyze_health_logic(units=units, dbus_manager=dbus_manager)
        if result:
            if output == "rich":
                format_health_report(result, CONSOLE)
            elif output == "json":
                print(json.dumps(asdict(result), indent=2, default=str))
            else:
                log.error(f"Unsupported output format: {output}")
                raise typer.Exit(code=1)
        else:
            log.error("Health analysis failed to produce results.")
            raise typer.Exit(code=1)
    except Exception as e:
        log.exception(f"An unexpected error occurred: {e}")
        raise typer.Exit(code=1)

@app.command()
def analyze_resources(
    output: str = typer.Option("rich", "--output", "-o", help="Output format ('rich' or 'json')."),
):
    """Analyze system and unit resource use (incl. child process groups)."""
    check_privileges()
    log.info("Starting resource-only analysis...")
    try:
        dbus_manager = _get_systemd_manager_interface()
        # Fetch units first
        units, fetch_error = [], None
        if dbus_manager:
            units, fetch_error = _get_all_units_dbus(dbus_manager)
        if fetch_error or not units:
            units, fetch_error = _get_all_units_json()
        if fetch_error and not units:
            log.error(f"Failed to fetch units: {fetch_error}")
            raise typer.Exit(code=1)
        if not units:
            log.warning("No units found.")
            CONSOLE.print("[yellow]No units found.[/yellow]")
            raise typer.Exit(code=0)

        # Pass fetched units to analysis function
        result = analyze_resources_logic(units=units, dbus_manager=dbus_manager)
        if result:
            if output == "rich":
                format_resource_report(result, CONSOLE)
            elif output == "json":
                print(json.dumps(asdict(result), indent=2, default=str))
            else:
                log.error(f"Unsupported output format: {output}")
                raise typer.Exit(code=1)
        else:
            log.error("Resource analysis failed to produce results.")
            raise typer.Exit(code=1)
    except Exception as e:
        log.exception(f"An unexpected error occurred: {e}")
        raise typer.Exit(code=1)

@app.command()
def analyze_logs(
    output: str = typer.Option("rich", "--output", "-o", help="Output format ('rich' or 'json')."),
    boot: int = typer.Option(0, "--boot", "-b", help="Boot offset (0=current, -1=previous, etc.)."),
    priority: int = typer.Option(DEFAULT_ANALYSIS_LEVEL, "--priority", "-p", min=0, max=7, help="Minimum priority level to analyze (0=emerg..7=debug)."),
):
    """Analyze system logs for OOM events and common error/warning patterns."""
    # (Logic remains the same)
    check_privileges()
    log.info(f"Starting log-only analysis (boot={boot}, min_priority={priority})...")
    try:
        result = analyze_logs_logic(boot_offset=boot, min_priority=priority)
        if result:
            if output == "rich":
                format_log_report(result, CONSOLE)
            elif output == "json":
                print(json.dumps(asdict(result), indent=2, default=str))
            else:
                log.error(f"Unsupported output format: {output}")
                raise typer.Exit(code=1)
        else:
            log.error("Log analysis failed to produce results.")
            raise typer.Exit(code=1)
    except Exception as e:
        log.exception(f"An unexpected error occurred: {e}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
