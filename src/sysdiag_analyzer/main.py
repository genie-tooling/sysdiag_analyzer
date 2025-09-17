# src/sysdiag_analyzer/main.py
import logging
import os
import time
import platform
import datetime
import json
import gzip
import shutil
from pathlib import Path
from typing import Optional, List, Dict, Any
import threading

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict

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
    EBPFAnalysisResult,
    BootTimes,
    UnitHealthInfo,
)
from .modules.boot import analyze_boot as analyze_boot_logic
from .modules.health import (
    analyze_health as analyze_health_logic,
    _get_systemd_manager_interface,
    _get_all_units_dbus,
    _get_all_units_json,
)
from .modules.resources import analyze_resources as analyze_resources_logic
from .modules.logs import (
    analyze_general_logs as analyze_logs_logic,
    DEFAULT_ANALYSIS_LEVEL,
)
from .modules.dependencies import (
    analyze_dependencies as analyze_dependencies_logic,
    analyze_full_dependency_graph,
)
from . import features
from .unit_analyzer import run_single_unit_analysis

from .output import (
    format_rich_report,
    format_json_report,
    format_boot_report,
    format_health_report,
    format_resource_report,
    format_log_report,
    format_rich_single_unit_report,
    format_json_single_unit_report,
)
from .utils import get_boot_id, deduplicate_device_units
from .config import load_config, DEFAULT_CONFIG

try:
    from . import ml_engine

    HAS_ML_ENGINE = ml_engine.HAS_ML_LIBS
except ImportError:
    ml_engine = None
    HAS_ML_ENGINE = False

try:
    from . import llm_analyzer

    HAS_LLM_OLLAMA = llm_analyzer.HAS_OLLAMA
    HAS_LLM_ENGINE = True
except ImportError:
    llm_analyzer = None
    HAS_LLM_ENGINE = False
    HAS_LLM_OLLAMA = False

EXPORTER_IMPORT_ERROR: Optional[ImportError] = None
try:
    from . import exporter as exporter_logic
    from prometheus_client import start_http_server, REGISTRY  # type: ignore

    HAS_EXPORTER_LIBS = exporter_logic.HAS_PROMETHEUS_LIBS
    if not HAS_EXPORTER_LIBS:
        EXPORTER_IMPORT_ERROR = getattr(exporter_logic, "PROMETHEUS_IMPORT_ERROR", None)

except ImportError as e:
    exporter_logic = None
    start_http_server = None
    REGISTRY = None
    HAS_EXPORTER_LIBS = False
    EXPORTER_IMPORT_ERROR = e


LOG_LEVEL = logging.INFO

CONSOLE = Console()
CONSOLE_ERR = Console(stderr=True)

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=CONSOLE_ERR, rich_tracebacks=True, show_path=False)],
)
log = logging.getLogger(__name__)

app = typer.Typer(
    help="Sysdiag-Analyzer: Systemd & System Health Diagnostic Tool with ML, LLM & eBPF."
)


def check_privileges(required_for: str = "some checks") -> bool:
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


def _save_report(report: SystemReport, history_dir: Path):
    log.info("Attempting to save analysis report...")
    boot_id = report.boot_id or get_boot_id() or "unknown_boot"
    timestamp_str = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )
    filename = history_dir / f"report-{boot_id}-{timestamp_str}.jsonl.gz"

    try:
        history_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    except PermissionError:
        log.error(f"Permission denied creating history directory: {history_dir}")
        report.errors.append("Failed to save report: Cannot create history directory.")
        return
    except Exception as e:
        log.error(f"Error creating history directory {history_dir}: {e}")
        report.errors.append(
            f"Failed to save report: Error creating history directory: {e}"
        )
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
        log.error(
            f"Failed to write compressed report to {filename}: {e}", exc_info=True
        )
        report.errors.append(f"Failed to save report: File write error: {e}")
    except Exception as e:
        log.error(f"Unexpected error saving report {filename}: {e}", exc_info=True)
        report.errors.append(f"Failed to save report: Unexpected error: {e}")


def _apply_retention(history_dir: Path, max_files: int):
    log.info(f"Applying retention policy (max {max_files} files) in {history_dir}...")
    try:
        history_files = sorted(
            history_dir.glob("report-*.jsonl.gz"), key=os.path.getmtime
        )
        files_to_delete_count = len(history_files) - max_files
        if files_to_delete_count > 0:
            log.info(
                f"Found {len(history_files)} reports, keeping {max_files}, deleting {files_to_delete_count}."
            )
            for i in range(files_to_delete_count):
                file_to_delete = history_files[i]
                try:
                    log.debug(f"Deleting old report: {file_to_delete}")
                    file_to_delete.unlink()
                except FileNotFoundError:
                    log.warning(
                        f"File not found during deletion (likely race condition): {file_to_delete}"
                    )
                except (OSError, PermissionError) as delete_e:
                    log.error(
                        f"Failed to delete old report {file_to_delete}: {delete_e}"
                    )
        else:
            log.debug("No old reports need deletion.")
    except Exception as e:
        log.error(
            f"Error applying retention policy in {history_dir}: {e}", exc_info=True
        )


def _run_core_analyses(
    report: SystemReport,
    all_units: List[UnitHealthInfo],
    dbus_manager: Optional[Any],
    analyze_full_graph: bool,
) -> SystemReport:
    try:
        report.boot_analysis = analyze_boot_logic()
    except Exception as e:
        log.exception("Error during boot analysis.")
        report.errors.append(f"Boot analysis failed: {e}")
        if report.boot_analysis is None:
            report.boot_analysis = BootAnalysisResult()
        if report.boot_analysis.times is None:
            report.boot_analysis.times = BootTimes()
        report.boot_analysis.times.error = (
            report.boot_analysis.times.error or f"Failed to get result: {e}"
        )

    try:
        report.health_analysis = analyze_health_logic(
            units=all_units, dbus_manager=dbus_manager
        )
    except Exception as e:
        log.exception("Error during health analysis.")
        report.errors.append(f"Health analysis failed: {e}")
        if report.health_analysis is None:
            report.health_analysis = HealthAnalysisResult(
                analysis_error=f"Failed to get result: {e}"
            )
        else:
            report.health_analysis.analysis_error = (
                report.health_analysis.analysis_error or f"Failed to get result: {e}"
            )

    try:
        report.resource_analysis = analyze_resources_logic(
            units=all_units, dbus_manager=dbus_manager
        )
    except Exception as e:
        log.exception("Error during resource analysis.")
        report.errors.append(f"Resource analysis failed: {e}")
        if report.resource_analysis is None:
            report.resource_analysis = ResourceAnalysisResult(
                analysis_error=f"Failed to get result: {e}"
            )
        else:
            report.resource_analysis.analysis_error = (
                report.resource_analysis.analysis_error or f"Failed to get result: {e}"
            )

    try:
        failed_units_to_analyze = (
            report.health_analysis.failed_units if report.health_analysis else []
        )
        if failed_units_to_analyze:
            log.info(
                f"Running dependency analysis for {len(failed_units_to_analyze)} failed units..."
            )
            report.dependency_analysis = analyze_dependencies_logic(
                failed_units=failed_units_to_analyze, dbus_manager=dbus_manager
            )
        else:
            log.info("Skipping dependency analysis: No failed units identified.")
            report.dependency_analysis = DependencyAnalysisResult()
    except Exception as e:
        log.exception("Error during dependency analysis.")
        report.errors.append(f"Dependency analysis failed: {e}")
        if report.dependency_analysis is None:
            report.dependency_analysis = DependencyAnalysisResult(
                analysis_error=f"Failed to get result: {e}"
            )
        else:
            report.dependency_analysis.analysis_error = (
                report.dependency_analysis.analysis_error or f"Failed to get result: {e}"
            )

    if analyze_full_graph:
        log.info("Full dependency graph analysis requested.")
        try:
            report.full_dependency_analysis = analyze_full_dependency_graph()
            if (
                report.full_dependency_analysis
                and report.full_dependency_analysis.analysis_error
            ):
                report.errors.append(
                    f"Full Graph Analysis: {report.full_dependency_analysis.analysis_error}"
                )
        except Exception as e:
            log.exception("Error during full dependency graph analysis.")
            err_msg = f"Full dependency graph analysis failed: {e}"
            report.errors.append(err_msg)
            if report.full_dependency_analysis is None:
                report.full_dependency_analysis = FullDependencyAnalysisResult(
                    analysis_error=err_msg
                )
            report.full_dependency_analysis.analysis_error = err_msg
    else:
        log.info("Skipping full dependency graph analysis (flag not set).")

    try:
        report.log_analysis = analyze_logs_logic()
    except Exception as e:
        log.exception("Error during log analysis.")
        report.errors.append(f"Log analysis failed: {e}")
        if report.log_analysis is None:
            report.log_analysis = LogAnalysisResult(
                analysis_error=f"Failed to get result: {e}"
            )
        else:
            report.log_analysis.analysis_error = (
                report.log_analysis.analysis_error or f"Failed to get result: {e}"
            )

    return report


def run_full_analysis(
    history_dir: Path,
    model_dir: Path,
    all_units: List[UnitHealthInfo],
    dbus_manager: Optional[Any],
    app_config: Dict[str, Any],
    since: Optional[str] = None,
    enable_ebpf: bool = False,
    analyze_full_graph: bool = False,
    analyze_ml: bool = False,
    analyze_llm: bool = False,
    llm_config: Optional[Dict[str, Any]] = None,
) -> SystemReport:
    log.info("Starting full system analysis...")
    is_root = check_privileges(
        required_for="eBPF tracing, cgroup access, DBus, journal"
    )

    current_boot_id = get_boot_id()
    report = SystemReport(
        hostname=platform.node(),
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        boot_id=current_boot_id,
    )

    if not all_units:
        log.warning(
            "run_full_analysis received empty unit list. Analysis will be limited."
        )
        report.errors.append("Analysis performed with empty unit list.")

    ebpf_collector = None
    if enable_ebpf:
        ebpf_monitor = None
        HAS_BCC = False
        try:
            from .modules import ebpf_monitor

            HAS_BCC = ebpf_monitor.HAS_BCC
        except ImportError as e:
            log.warning(
                f"Could not import ebpf_monitor module: {e}. eBPF features disabled.",
                exc_info=False,
            )

        if not is_root or not ebpf_monitor or not HAS_BCC:
            error_msg = ""
            if not is_root:
                error_msg = "Root privileges required."
            elif not ebpf_monitor:
                error_msg = (
                    "eBPF module could not be loaded (check system dependencies)."
                )
            elif not HAS_BCC:
                error_msg = "'bcc' library missing (install sysdiag-analyzer[ebpf])."

            log.error(
                f"eBPF analysis requested, but prerequisites not met: {error_msg}"
            )
            report.errors.append(f"eBPF analysis skipped: {error_msg}")
            report.ebpf_analysis = EBPFAnalysisResult(error=error_msg)
        else:
            try:
                log.info("Initializing eBPF monitoring...")
                ebpf_collector = ebpf_monitor.EBPFCollector()
                ebpf_collector.start()
                log.info(
                    "eBPF monitoring started. Running core analysis in background..."
                )

                with ThreadPoolExecutor(
                    max_workers=1, thread_name_prefix="CoreAnalysis"
                ) as executor:
                    analysis_future = executor.submit(
                        _run_core_analyses,
                        report,
                        all_units,
                        dbus_manager,
                        analyze_full_graph,
                    )
                    while not analysis_future.done():
                        ebpf_collector.poll_events(timeout_ms=100)
                        time.sleep(0.1)

                    report = analysis_future.result()
                    log.info("Core analysis finished.")

            except Exception as e:
                log.exception(
                    "Failed to initialize or run eBPF monitoring concurrently."
                )
                report.errors.append(f"eBPF initialization/run failed: {e}")
                report.ebpf_analysis = EBPFAnalysisResult(
                    error=f"Initialization failed: {e}"
                )
                if ebpf_collector and ebpf_collector._running:
                    ebpf_collector.stop()
                ebpf_collector = None
    else:
        log.info("Skipping eBPF analysis (flag not set). Running core analysis synchronously.")
        report = _run_core_analyses(report, all_units, dbus_manager, analyze_full_graph)

    if ebpf_collector:
        log.info("Stopping eBPF monitoring and collecting events...")
        try:
            if "ebpf_monitor" in locals() and ebpf_monitor:
                report.ebpf_analysis = ebpf_collector.stop()
                log.info(
                    f"Collected {len(report.ebpf_analysis.exec_events)} exec events and {len(report.ebpf_analysis.exit_events)} exit events."
                )
        except Exception as e:
            log.exception("Error stopping eBPF monitoring.")
            err_msg = f"eBPF data collection failed: {e}"
            report.errors.append(err_msg)
            if report.ebpf_analysis is None:
                report.ebpf_analysis = EBPFAnalysisResult()
            report.ebpf_analysis.error = err_msg

    if analyze_ml:
        log.info("ML analysis requested.")
        ml_result = MLAnalysisResult()
        report.ml_analysis = ml_result
        if not HAS_ML_ENGINE or not ml_engine:
            ml_result.error = "ML dependencies not installed. Skipping ML analysis."
            log.error(ml_result.error)
        else:
            try:
                log.info("Filtering for active services with a PID for ML analysis...")
                active_services_with_pid = []
                for unit in all_units:
                    if not unit.name.endswith(".service"):
                        continue
                    pid_val = unit.details.get("MainPID")
                    if pid_val is not None:
                        try:
                            if int(pid_val) > 0:
                                active_services_with_pid.append(unit)
                        except (ValueError, TypeError):
                            continue

                active_service_names = {unit.name for unit in active_services_with_pid}
                log.info(
                    f"Found {len(active_service_names)} active services with a PID to analyze."
                )

                if not active_service_names:
                    ml_result.error = "No active services with a PID found to analyze."
                    log.warning(ml_result.error)
                else:
                    log.info(
                        f"Loading ML models from {model_dir} for {len(active_service_names)} active services..."
                    )
                    anomaly_models, scalers, thresholds = ml_engine.load_models(
                        model_dir, active_units=active_service_names
                    )
                    ml_result.models_loaded_count = len(anomaly_models)

                    if not all([anomaly_models, scalers, thresholds]):
                        ml_result.error = "No relevant pre-trained models found for active services. Run 'retrain-ml' first."
                        log.warning(ml_result.error)
                    else:
                        log.info(
                            "Preparing data sequence for time-series anomaly detection..."
                        )
                        timesteps = app_config.get("models", {}).get(
                            "lstm_timesteps", ml_engine.LSTM_TIMESTEPS
                        )
                        historical_reports = features.load_historical_data(
                            history_dir, num_reports=(timesteps - 1)
                        )
                        current_report_dict = asdict(report)
                        all_reports_for_ml = historical_reports + [current_report_dict]

                        log.info(
                            f"Extracting features from {len(all_reports_for_ml)} reports for ML analysis..."
                        )
                        features_list = features.extract_features(all_reports_for_ml)

                        if not features_list:
                            ml_result.error = "No features extracted from recent reports for ML analysis."
                        else:
                            features_df = ml_engine.pd.DataFrame(features_list)
                            features_df[
                                "report_timestamp"
                            ] = ml_engine.pd.to_datetime(
                                features_df["report_timestamp"]
                            )
                            engineered_df = ml_engine.engineer_features(features_df)

                            if engineered_df.empty:
                                log.warning(
                                    "Feature engineering resulted in empty DataFrame."
                                )
                            else:
                                df_for_detection = engineered_df[
                                    engineered_df["unit_name"].isin(active_service_names)
                                ].copy()

                                if df_for_detection.empty:
                                    log.warning(
                                        "No feature data available for the filtered active services."
                                    )
                                    ml_result.units_analyzed_count = 0
                                else:
                                    ml_result.units_analyzed_count = (
                                        df_for_detection["unit_name"].nunique()
                                    )
                                    log.info(
                                        f"Running anomaly detection for {ml_result.units_analyzed_count} active services..."
                                    )
                                    anomalies = ml_engine.detect_anomalies(
                                        df_for_detection,
                                        anomaly_models,
                                        scalers,
                                        thresholds,
                                    )
                                    ml_result.anomalies_detected = anomalies
            except Exception as e:
                log.exception("An unexpected error occurred during ML analysis.")
                ml_result.error = f"ML analysis failed: {e}"

    if analyze_llm:
        log.info("LLM synthesis requested.")
        if not llm_config:
            report.llm_analysis = LLMAnalysisResult(error="LLM config not provided.")
        elif not HAS_LLM_ENGINE or not llm_analyzer:
            report.llm_analysis = LLMAnalysisResult(
                error="LLM module failed to load or dependencies are missing."
            )
        else:
            try:
                log.info(
                    f"Invoking LLM analysis with model '{llm_config.get('model')}'..."
                )
                report.llm_analysis = llm_analyzer.analyze_with_llm(
                    report=report, llm_config=llm_config, history_dir=history_dir
                )
            except Exception as e:
                log.exception("An unexpected error occurred during LLM analysis.")
                report.llm_analysis = LLMAnalysisResult(
                    error=f"LLM analysis failed: {e}"
                )

    log.info("Full system analysis finished.")
    return report


config_app = typer.Typer(help="Manage sysdiag-analyzer configuration.")
app.add_typer(config_app, name="config")


@config_app.command("show")
def config_show(
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to a specific TOML configuration file to load.",
        exists=False,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
):
    """Display the currently loaded configuration (merged from defaults and files)."""
    try:
        loaded_conf = load_config(config_path_override=config_file)
        conf_json = json.dumps(loaded_conf, indent=2, default=str)
        syntax = Syntax(conf_json, "json", theme="default", line_numbers=True)
        CONSOLE.print(Panel(syntax, title="Loaded Configuration", border_style="blue"))
    except Exception as e:
        log.exception("Failed to load or display configuration.")
        CONSOLE_ERR.print(
            f"[bold red]Error:[/bold red] Failed to load or display configuration: {e}"
        )
        raise typer.Exit(code=1)


@app.command()
def run(
    since: Optional[str] = typer.Option(
        None,
        "--since",
        help="Analyze logs since this time (e.g., '1 hour ago', 'yesterday') - Not Implemented Yet.",
    ),
    output: str = typer.Option(
        "rich", "--output", "-o", help="Output format ('rich' or 'json')."
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to a custom TOML configuration file.",
        exists=False,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    enable_ebpf: bool = typer.Option(
        False,
        "--enable-ebpf",
        help="Enable eBPF-based process tracing (requires root and bcc).",
    ),
    analyze_full_graph: bool = typer.Option(
        False,
        "--analyze-full-graph",
        help="Perform full dependency graph analysis to detect cycles (requires networkx).",
    ),
    analyze_ml: bool = typer.Option(
        False,
        "--analyze-ml",
        help="Perform ML-based anomaly detection (requires trained models).",
    ),
    analyze_llm: bool = typer.Option(
        False,
        "--analyze-llm",
        help="Perform LLM-based synthesis of the report (requires configuration and Ollama).",
    ),
    llm_model: Optional[str] = typer.Option(
        None, "--llm-model", help="Override the LLM model specified in the config file."
    ),
    no_save: bool = typer.Option(
        False,
        "--no-save",
        help="Do not save the analysis report to the history directory.",
    ),
):
    report: Optional[SystemReport] = None
    try:
        app_config = load_config(config_path_override=config_file)
        current_history_dir = Path(
            app_config.get("history", {}).get(
                "directory", DEFAULT_CONFIG["history"]["directory"]
            )
        )
        current_max_history = app_config.get("history", {}).get(
            "max_files", DEFAULT_CONFIG["history"]["max_files"]
        )
        current_model_dir = Path(
            app_config.get("models", {}).get(
                "directory", DEFAULT_CONFIG["models"]["directory"]
            )
        )

        effective_llm_config = None
        if analyze_llm:
            log.debug("Performing pre-analysis LLM configuration checks...")
            llm_config_section = app_config.get("llm", {})
            provider_name = llm_config_section.get("provider")
            effective_model_name = llm_model or llm_config_section.get("model")
            if not HAS_LLM_ENGINE:
                CONSOLE_ERR.print(
                    "[bold red]Error:[/bold red] LLM analysis requested, but LLM dependencies are not installed."
                )
                CONSOLE_ERR.print(
                    "Install with: [cyan]pip install sysdiag-analyzer[llm][/cyan]"
                )
                raise typer.Exit(code=1)
            if not provider_name:
                CONSOLE_ERR.print(
                    "[bold red]Error:[/bold red] LLM analysis requested, but 'provider' is not specified in the \\[llm] section of the configuration file."
                )
                raise typer.Exit(code=1)
            if not effective_model_name:
                CONSOLE_ERR.print(
                    "[bold red]Error:[/bold red] LLM analysis requested, but 'model' is not specified in the \\[llm] section of the configuration file and not provided via --llm-model."
                )
                raise typer.Exit(code=1)
            if provider_name == "ollama" and not HAS_LLM_OLLAMA:
                CONSOLE_ERR.print(
                    "[bold red]Error:[/bold red] LLM provider 'ollama' configured, but the 'ollama' library is not installed."
                )
                CONSOLE_ERR.print(
                    "Install with: [cyan]pip install sysdiag-analyzer[llm][/cyan]"
                )
                raise typer.Exit(code=1)
            effective_llm_config = llm_config_section.copy()
            effective_llm_config["model"] = effective_model_name
            log.debug("LLM pre-analysis configuration checks passed.")

        dbus_manager = _get_systemd_manager_interface()
        all_units: List[UnitHealthInfo] = []
        fetch_error: Optional[str] = None
        log.info("Fetching unit list...")
        if dbus_manager:
            all_units, fetch_error = _get_all_units_dbus(dbus_manager)
            if fetch_error or not all_units:
                log.warning(
                    f"DBus ListUnits failed or returned empty ({fetch_error}), attempting systemctl fallback..."
                )
                all_units, fetch_error = _get_all_units_json()
        else:
            log.info(
                "DBus manager not available or DBus not installed, using systemctl fallback for unit list."
            )
            all_units, fetch_error = _get_all_units_json()

        if all_units:
            all_units = deduplicate_device_units(all_units)

        if fetch_error:
            if not all_units:
                log.error(f"Failed to get unit list: {fetch_error}")
                CONSOLE_ERR.print(
                    f"[bold red]Error:[/bold red] Failed to retrieve unit list ({fetch_error}). Analysis cannot proceed."
                )
                raise typer.Exit(code=1)
            else:
                log.warning(
                    f"Initial unit fetch failed ({fetch_error}), but fallback succeeded."
                )
        elif not all_units:
            log.warning("No units found for analysis.")
            CONSOLE_ERR.print(
                "[yellow]Warning:[/yellow] No systemd units found. Analysis may be incomplete."
            )

        report = run_full_analysis(
            history_dir=current_history_dir,
            model_dir=current_model_dir,
            all_units=all_units,
            dbus_manager=dbus_manager,
            app_config=app_config,
            since=since,
            enable_ebpf=enable_ebpf,
            analyze_full_graph=analyze_full_graph,
            analyze_ml=analyze_ml,
            analyze_llm=analyze_llm,
            llm_config=effective_llm_config,
        )

        if not no_save:
            if report:
                _save_report(report, current_history_dir)
                _apply_retention(current_history_dir, current_max_history)
            else:
                log.error("Analysis failed to produce a report, cannot save.")
        else:
            log.info("Skipping report saving as per --no-save flag.")

        if output == "rich":
            format_rich_report(report, CONSOLE)
        elif output == "json":
            CONSOLE.print(format_json_report(report))
        else:
            log.error(f"Unsupported output format: {output}")
            raise typer.Exit(code=1)

        exit_code = 0
        if report:
            if report.health_analysis and report.health_analysis.failed_units:
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
            log.warning(
                f"Exiting with code {exit_code} due to detected issues or errors."
            )
            raise typer.Exit(code=exit_code)

    except typer.Exit:
        raise
    except Exception as e:
        log.exception(f"An unexpected error occurred during command 'run': {e}")
        if not isinstance(e, typer.Exit):
            raise typer.Exit(code=1)


@app.command()
def exporter(
    host: str = typer.Option(
        "0.0.0.0", "--host", help="The host address to bind the Prometheus exporter to."
    ),
    port: int = typer.Option(
        9822, "--port", help="The port to expose the Prometheus exporter on."
    ),
    interval: int = typer.Option(
        60,
        "--interval",
        "-i",
        help="The interval in seconds between background data collection runs.",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to a custom TOML configuration file.",
        exists=False,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
):
    """
    Run a persistent Prometheus exporter.
    This command starts a web server to expose sysdiag-analyzer's unique metrics.
    It periodically runs a targeted analysis in the background to refresh the metrics.
    """
    check_privileges(required_for="DBus, journal, and cgroup access")
    if not HAS_EXPORTER_LIBS:
        CONSOLE_ERR.print(
            "[bold red]Error:[/bold red] Prometheus exporter dependencies are not installed."
        )
        if EXPORTER_IMPORT_ERROR:
            CONSOLE_ERR.print(f"[dim]Reason: {EXPORTER_IMPORT_ERROR}[/dim]")
        CONSOLE_ERR.print(
            "Install with: [cyan]pip install 'sysdiag-analyzer[exporter]'[/cyan]"
        )
        raise typer.Exit(code=1)

    try:
        log.info("Starting Sysdiag-Analyzer Prometheus Exporter...")
        app_config = load_config(config_path_override=config_file)

        collector = exporter_logic.SysdiagCollector(
            config=app_config, interval=interval
        )
        REGISTRY.register(collector)

        analysis_thread = threading.Thread(
            target=collector.run_periodic_analysis,
            name="SysdiagPeriodicAnalysis",
            daemon=True,
        )
        analysis_thread.start()

        start_http_server(port, addr=host)
        log.info(f"Exporter started. Listening on http://{host}:{port}")
        CONSOLE.print(
            f"✅ [bold green]Prometheus exporter is running on http://{host}:{port}[/bold green]"
        )
        CONSOLE.print("Press Ctrl+C to exit.")

        while True:
            time.sleep(1)

    except (ImportError, ModuleNotFoundError) as e:
        CONSOLE_ERR.print(
            f"[bold red]Error:[/bold red] Missing dependency for exporter: {e}"
        )
        CONSOLE_ERR.print(
            "Install with: [cyan]pip install 'sysdiag-analyzer[exporter]'[/cyan]"
        )
        raise typer.Exit(code=1)
    except OSError as e:
        log.exception(
            f"Failed to start exporter, likely a port conflict on {host}:{port}."
        )
        CONSOLE_ERR.print(f"[bold red]Error starting exporter:[/bold red] {e}")
        CONSOLE_ERR.print("Is another process already using that port?")
        raise typer.Exit(code=1)
    except Exception as e:
        log.exception("An unexpected error occurred in the exporter.")
        CONSOLE_ERR.print(f"[bold red]An unexpected error occurred:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command()
def retrain_ml(
    num_reports: int = typer.Option(
        300,
        "--num-reports",
        "-n",
        help="Number of recent history reports to use for training.",
    ),
    train_devices: bool = typer.Option(
        False,
        "--train-devices",
        help="Include device, slice, and scope units in ML training. [bold yellow]Warning:[/bold yellow] This is highly memory-intensive and may fail on systems with <32GB RAM.",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to a custom TOML configuration file.",
        exists=False,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
):
    log.info("Starting ML model retraining process...")
    check_privileges(required_for="saving models to default location")

    app_config = load_config(config_path_override=config_file)
    current_history_dir = Path(
        app_config.get("history", {}).get(
            "directory", DEFAULT_CONFIG["history"]["directory"]
        )
    )
    current_model_dir = Path(
        app_config.get("models", {}).get(
            "directory", DEFAULT_CONFIG["models"]["directory"]
        )
    )
    if ml_engine:
        models_cfg = app_config.get("models", {})
        ml_engine.LSTM_TIMESTEPS = models_cfg.get(
            "lstm_timesteps", ml_engine.LSTM_TIMESTEPS
        )
        ml_engine.MIN_SAMPLES_FOR_TRAINING = models_cfg.get(
            "min_samples_train", ml_engine.MIN_SAMPLES_FOR_TRAINING
        )

    if not HAS_ML_ENGINE or not ml_engine:
        CONSOLE_ERR.print(
            "[red]Error: ML dependencies (pandas, scikit-learn, tensorflow) not installed. Cannot retrain.[/red]"
        )
        CONSOLE_ERR.print("Install with: pip install sysdiag-analyzer[ml]")
        raise typer.Exit(code=1)

    if not current_model_dir.exists():
        try:
            log.info(f"Attempting to create model directory: {current_model_dir}")
            current_model_dir.mkdir(parents=True, mode=0o700)
        except PermissionError:
            CONSOLE_ERR.print(
                f"[red]Error: Permission denied creating model directory: {current_model_dir}. Run with sudo?[/red]"
            )
            raise typer.Exit(code=1)
        except Exception as e:
            CONSOLE_ERR.print(
                f"[red]Error creating model directory {current_model_dir}: {e}[/red]"
            )
            raise typer.Exit(code=1)

    try:
        # Step 1: Load and prepare data
        features_df = ml_engine.load_and_prepare_data(
            history_dir=current_history_dir,
            num_reports=num_reports,
            include_devices=train_devices,
        )
        if features_df is None or features_df.empty:
            CONSOLE.print(
                "[yellow]Warning: No data available for training. Ensure history reports exist.[/yellow]"
            )
            raise typer.Exit(code=0)

        # Step 2: Engineer features
        engineered_df = ml_engine.engineer_features(features_df)
        if engineered_df is None or engineered_df.empty:
            CONSOLE_ERR.print("[red]Error: Feature engineering failed. Check logs.[/red]")
            raise typer.Exit(code=1)

        # Step 3: Train models
        trained_count, skipped_summary = ml_engine.train_anomaly_models(
            engineered_df=engineered_df,
            model_dir_path=current_model_dir,
            # Let's default to a reasonable number of workers
            max_workers=os.cpu_count() or 1,
        )

        if not trained_count and not skipped_summary:
            CONSOLE.print(
                "[yellow]Warning: No models were trained and no units were skipped. The dataset might be empty after engineering.[/yellow]"
            )
        else:
            CONSOLE.print(
                f"✅ [green]Successfully trained and saved {trained_count} anomaly models to {current_model_dir}.[/green]"
            )

        if skipped_summary:
            total_skipped = sum(len(units) for units in skipped_summary.values())
            CONSOLE.print(
                f"\n[bold yellow]Skipped a total of {total_skipped} units for the following reasons:[/bold yellow]"
            )
            table = Table(box=None, show_header=False, expand=False, padding=(0, 1))
            table.add_column("Reason", style="yellow", no_wrap=True)
            table.add_column("Count", style="magenta", justify="right")
            table.add_column("Examples", style="dim")

            for reason, units in sorted(skipped_summary.items()):
                examples = ", ".join(units[:3])
                if len(units) > 3:
                    examples += ", ..."
                table.add_row(reason, str(len(units)), f" (e.g., {examples})")

            CONSOLE.print(table)

    except PermissionError as e:
        log.error(f"Permission denied during model saving: {e}")
        CONSOLE_ERR.print(
            f"[red]Error: Permission denied saving models to {current_model_dir}. Run with sudo?[/red]"
        )
        raise typer.Exit(code=1)
    except Exception as e:
        log.exception(f"An unexpected error occurred during ML retraining: {e}")
        CONSOLE_ERR.print(
            f"[red]An unexpected error occurred during retraining: {e}[/red]"
        )
        raise typer.Exit(code=1)

    log.info("ML model retraining finished.")


@app.command()
def prune_ml_models(
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Automatically confirm and delete obsolete models without prompting.",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to a custom TOML configuration file.",
        exists=False,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
):
    """
    Scans for and removes obsolete ML models.
    This command compares the models in the models directory against the units
    currently active on the system and removes any that are no longer present.
    """
    check_privileges(required_for="listing units and deleting model files")
    app_config = load_config(config_path_override=config_file)
    current_model_dir = Path(
        app_config.get("models", {}).get(
            "directory", DEFAULT_CONFIG["models"]["directory"]
        )
    )

    if not HAS_ML_ENGINE or not ml_engine:
        CONSOLE_ERR.print(
            "[red]Error: ML dependencies not installed. Cannot perform model operations.[/red]"
        )
        raise typer.Exit(code=1)

    if not current_model_dir.is_dir():
        CONSOLE.print(f"[dim]Model directory not found at {current_model_dir}. Nothing to prune.[/dim]")
        raise typer.Exit()

    # 1. Get current units on the system
    dbus_manager = _get_systemd_manager_interface()
    all_units, fetch_error = [], None
    if dbus_manager:
        all_units, _ = _get_all_units_dbus(dbus_manager)
    if not all_units:
        all_units, fetch_error = _get_all_units_json()

    if fetch_error:
        CONSOLE_ERR.print(f"[red]Error: Could not fetch current system units: {fetch_error}[/red]")
        raise typer.Exit(code=1)

    current_sanitized_names = {ml_engine._sanitize_filename(u.name) for u in all_units}
    log.info(f"Found {len(current_sanitized_names)} unique, active units on the system.")

    # 2. Get trained models from the directory
    trained_model_dirs = [d for d in current_model_dir.iterdir() if d.is_dir()]
    trained_sanitized_names = {d.name for d in trained_model_dirs}
    log.info(f"Found {len(trained_sanitized_names)} trained models in {current_model_dir}.")

    # 3. Find the difference
    obsolete_names = trained_sanitized_names - current_sanitized_names

    if not obsolete_names:
        CONSOLE.print("✅ [green]Model directory is clean. No obsolete models found.[/green]")
        raise typer.Exit()

    # 4. Confirm and delete
    CONSOLE.print(f"[bold yellow]Found {len(obsolete_names)} obsolete models to prune:[/bold yellow]")
    for name in sorted(list(obsolete_names))[:10]:
        CONSOLE.print(f"  - {name}")
    if len(obsolete_names) > 10:
        CONSOLE.print(f"  ... and {len(obsolete_names) - 10} more.")

    if not yes:
        confirmed = typer.confirm("\nAre you sure you want to permanently delete these model directories?")
        if not confirmed:
            CONSOLE.print("Pruning cancelled by user.")
            raise typer.Abort()

    deleted_count = 0
    error_count = 0
    for name in obsolete_names:
        model_path_to_delete = current_model_dir / name
        try:
            shutil.rmtree(model_path_to_delete)
            log.debug(f"Deleted obsolete model directory: {model_path_to_delete}")
            deleted_count += 1
        except Exception as e:
            log.error(f"Failed to delete directory {model_path_to_delete}: {e}")
            CONSOLE_ERR.print(f"[red]Error deleting {model_path_to_delete}: {e}[/red]")
            error_count += 1

    CONSOLE.print(f"\n[green]Pruning complete. Successfully deleted {deleted_count} model directories.[/green]")
    if error_count > 0:
        CONSOLE_ERR.print(f"[red]Failed to delete {error_count} model directories. Check logs for details.[/red]")
        raise typer.Exit(code=1)


@app.command()
def show_history(
    limit: int = typer.Option(
        5, "--limit", "-n", help="Number of recent reports to show metadata for."
    ),
    output: str = typer.Option(
        "rich", "--output", "-o", help="Output format ('rich' or 'json')."
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to a custom TOML configuration file.",
        exists=False,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
):
    app_config = load_config(config_path_override=config_file)
    current_history_dir = Path(
        app_config.get("history", {}).get(
            "directory", DEFAULT_CONFIG["history"]["directory"]
        )
    )

    log.info(
        f"Listing metadata for last {limit} reports from {current_history_dir}..."
    )
    if not current_history_dir.is_dir():
        CONSOLE_ERR.print(
            f"[yellow]History directory not found:[/yellow] {current_history_dir}"
        )
        raise typer.Exit(code=1)

    try:
        history_files = sorted(
            current_history_dir.glob("report-*.jsonl.gz"),
            key=os.path.getmtime,
            reverse=True,
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
                    ).isoformat(),
                }
                reports_meta.append(meta)
            except FileNotFoundError:
                log.warning(
                    f"History file disappeared while listing: {report_file.name}"
                )
            except OSError as stat_e:
                log.error(f"Could not stat history file {report_file.name}: {stat_e}")

        if not reports_meta:
            CONSOLE.print("[dim]No history reports found.[/dim]")
            return

        if output == "rich":
            from rich.table import Table

            table = Table(
                title=f"Recent Analysis Reports (Last {len(reports_meta)})",
                show_header=True,
                header_style="bold magenta",
            )
            table.add_column("#", style="dim", width=3)
            table.add_column("Filename", style="cyan", no_wrap=True)
            table.add_column("Size (KiB)", style="green", justify="right")
            table.add_column("Saved Timestamp (UTC)", style="yellow")
            for meta in reports_meta:
                table.add_row(
                    str(meta["index"]),
                    meta["filename"],
                    meta["size_kb"],
                    meta["modified_utc"],
                )
            CONSOLE.print(table)
        elif output == "json":
            CONSOLE.print(json.dumps(reports_meta, indent=2))
        else:
            log.error(f"Unsupported output format: {output}")
            raise typer.Exit(code=1)

    except Exception as e:
        log.exception(
            f"Error accessing or listing history directory {current_history_dir}: {e}"
        )
        raise typer.Exit(code=1)


@app.command()
def analyze_unit(
    unit_name: str = typer.Argument(
        ..., help="The name of the systemd unit to analyze (e.g., 'nginx.service')."
    ),
    output: str = typer.Option(
        "rich", "--output", "-o", help="Output format ('rich' or 'json')."
    ),
):
    """Perform a focused analysis on a specific systemd unit."""
    check_privileges(required_for="DBus, journal, and cgroup access")
    dbus_manager = _get_systemd_manager_interface()
    report = run_single_unit_analysis(unit_name, dbus_manager)

    if report.analysis_error:
        CONSOLE_ERR.print(f"[bold red]Error:[/bold red] {report.analysis_error}")
        raise typer.Exit(code=1)

    if output == "rich":
        format_rich_single_unit_report(report, CONSOLE)
    elif output == "json":
        CONSOLE.print(format_json_single_unit_report(report))
    else:
        log.error(f"Unsupported output format: {output}")
        raise typer.Exit(code=1)


@app.command()
def analyze_boot(
    output: str = typer.Option(
        "rich", "--output", "-o", help="Output format ('rich' or 'json')."
    ),
):
    check_privileges()
    log.info("Starting boot-only analysis...")
    try:
        result = analyze_boot_logic()
        if result:
            if output == "rich":
                format_boot_report(result, CONSOLE)
            elif output == "json":
                CONSOLE.print(json.dumps(asdict(result), indent=2, default=str))
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
    output: str = typer.Option(
        "rich", "--output", "-o", help="Output format ('rich' or 'json')."
    ),
):
    check_privileges()
    log.info("Starting health-only analysis...")
    try:
        dbus_manager = _get_systemd_manager_interface()
        units, fetch_error = [], None
        if dbus_manager:
            units, fetch_error = _get_all_units_dbus(dbus_manager)
        if fetch_error or not units:
            units, fetch_error = _get_all_units_json()

        if units:
            units = deduplicate_device_units(units)

        if fetch_error and not units:
            log.error(f"Failed to fetch units: {fetch_error}")
            raise typer.Exit(code=1)
        if not units:
            log.warning("No units found.")
            CONSOLE.print("[yellow]No units found.[/yellow]")
            raise typer.Exit(code=0)

        result = analyze_health_logic(units=units, dbus_manager=dbus_manager)
        if result:
            if output == "rich":
                format_health_report(result, CONSOLE)
            elif output == "json":
                CONSOLE.print(json.dumps(asdict(result), indent=2, default=str))
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
    output: str = typer.Option(
        "rich", "--output", "-o", help="Output format ('rich' or 'json')."
    ),
):
    check_privileges()
    log.info("Starting resource-only analysis...")
    try:
        dbus_manager = _get_systemd_manager_interface()
        units, fetch_error = [], None
        if dbus_manager:
            units, fetch_error = _get_all_units_dbus(dbus_manager)
        if fetch_error or not units:
            units, fetch_error = _get_all_units_json()

        if units:
            units = deduplicate_device_units(units)

        if fetch_error and not units:
            log.error(f"Failed to fetch units: {fetch_error}")
            raise typer.Exit(code=1)
        if not units:
            log.warning("No units found.")
            CONSOLE.print("[yellow]No units found.[/yellow]")
            raise typer.Exit(code=0)

        result = analyze_resources_logic(units=units, dbus_manager=dbus_manager)
        if result:
            if output == "rich":
                format_resource_report(result, CONSOLE)
            elif output == "json":
                CONSOLE.print(json.dumps(asdict(result), indent=2, default=str))
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
    output: str = typer.Option(
        "rich", "--output", "-o", help="Output format ('rich' or 'json')."
    ),
    boot: int = typer.Option(
        0, "--boot", "-b", help="Boot offset (0=current, -1=previous, etc.)."
    ),
    priority: int = typer.Option(
        DEFAULT_ANALYSIS_LEVEL,
        "--priority",
        "-p",
        min=0,
        max=7,
        help="Minimum priority level to analyze (0=emerg..7=debug).",
    ),
):
    check_privileges()
    log.info(f"Starting log-only analysis (boot={boot}, min_priority={priority})...")
    try:
        result = analyze_logs_logic(boot_offset=boot, min_priority=priority)
        if result:
            if output == "rich":
                format_log_report(result, CONSOLE)
            elif output == "json":
                CONSOLE.print(json.dumps(asdict(result), indent=2, default=str))
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
