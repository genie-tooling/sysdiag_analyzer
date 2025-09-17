from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

# Attempt import for type hinting if networkx is installed
try:
    from networkx import DiGraph  # type: ignore
except ImportError:
    DiGraph = Any  # type: ignore

# --- Boot Analysis Data Structures ---


@dataclass
class BootTimes:
    """Stores parsed times from 'systemd-analyze'."""

    firmware: Optional[str] = None
    loader: Optional[str] = None
    kernel: Optional[str] = None
    initrd: Optional[str] = None
    userspace: Optional[str] = None
    total: Optional[str] = None
    error: Optional[str] = None


@dataclass
class BootBlameItem:
    """Stores info for one unit from 'systemd-analyze blame'."""

    time: str
    unit: str


@dataclass
class CriticalChainItem:
    """Stores info for one unit from 'systemd-analyze critical-chain'."""

    unit: str
    time_at: Optional[str] = None
    time_delta: Optional[str] = None
    indent: int = 0


@dataclass
class BootAnalysisResult:
    """Aggregates all boot analysis results."""

    times: Optional[BootTimes] = None
    blame: List[BootBlameItem] = field(default_factory=list)
    critical_chain: List[CriticalChainItem] = field(default_factory=list)
    blame_error: Optional[str] = None
    critical_chain_error: Optional[str] = None


# --- Service Health Analysis Data Structures ---


@dataclass
class UnitHealthInfo:
    """Stores information about a single unit's health status."""

    name: str
    load_state: Optional[str] = None
    active_state: Optional[str] = None
    sub_state: Optional[str] = None
    description: Optional[str] = None
    path: Optional[str] = None
    is_failed: bool = False
    is_flapping: bool = False
    is_problematic_socket: bool = False
    is_problematic_timer: bool = False
    details: Dict[str, Any] = field(default_factory=dict)
    recent_logs: List[str] = field(default_factory=list)
    error_message: Optional[str] = None


@dataclass
class HealthAnalysisResult:
    """Aggregates all health findings."""

    failed_units: List[UnitHealthInfo] = field(default_factory=list)
    flapping_units: List[UnitHealthInfo] = field(default_factory=list)
    problematic_sockets: List[UnitHealthInfo] = field(default_factory=list)
    problematic_timers: List[UnitHealthInfo] = field(default_factory=list)
    all_units_count: int = 0
    analysis_error: Optional[str] = None


# --- Resource Utilization Analysis Data Structures ---


@dataclass
class SystemResourceUsage:
    """Stores system-wide resource usage metrics."""

    cpu_percent: Optional[float] = None
    mem_total_bytes: Optional[int] = None
    mem_available_bytes: Optional[int] = None
    mem_percent: Optional[float] = None
    swap_total_bytes: Optional[int] = None
    swap_used_bytes: Optional[int] = None
    swap_percent: Optional[float] = None
    disk_io_read_bytes: Optional[int] = None
    disk_io_write_bytes: Optional[int] = None
    net_io_sent_bytes: Optional[int] = None
    net_io_recv_bytes: Optional[int] = None
    error: Optional[str] = None


@dataclass
class UnitResourceUsage:
    """Stores resource usage metrics for a single systemd unit (cgroup based)."""

    name: str
    cgroup_path: Optional[str] = None
    cpu_usage_nsec: Optional[int] = None
    memory_current_bytes: Optional[int] = None
    memory_peak_bytes: Optional[int] = None
    io_read_bytes: Optional[int] = None
    io_write_bytes: Optional[int] = None
    tasks_current: Optional[int] = None
    error: Optional[str] = None


@dataclass
class ChildProcessGroupUsage:
    """Stores aggregated resource usage for a group of child processes."""

    command_name: str
    parent_unit: str
    process_count: int
    pids: List[int] = field(default_factory=list)
    # MODIFIED: Changed from percentage to cumulative seconds for accuracy.
    aggregated_cpu_seconds: Optional[float] = None
    aggregated_memory_bytes: Optional[int] = None


@dataclass
class ResourceAnalysisResult:
    """Aggregates all resource analysis findings."""

    system_usage: Optional[SystemResourceUsage] = None
    unit_usage: List[UnitResourceUsage] = field(default_factory=list)
    child_process_groups: List[ChildProcessGroupUsage] = field(default_factory=list)
    top_cpu_units: List[UnitResourceUsage] = field(default_factory=list)
    top_memory_units: List[UnitResourceUsage] = field(default_factory=list)
    top_io_units: List[UnitResourceUsage] = field(default_factory=list)
    analysis_error: Optional[str] = None


# --- Log Analysis Data Structures ---


@dataclass
class LogPatternInfo:
    """Stores info about occurrences of a specific log pattern."""

    pattern_type: str
    pattern_key: str
    count: int = 0
    level: Optional[str] = None
    example_messages: List[str] = field(default_factory=list)


@dataclass
class LogAnalysisResult:
    """Aggregates all log analysis findings."""

    detected_patterns: List[LogPatternInfo] = field(default_factory=list)
    total_entries_analyzed: int = 0
    log_source: Optional[str] = None
    analysis_error: Optional[str] = None


# --- Dependency Analysis Data Structures ---


@dataclass
class DependencyInfo:
    """Stores information about a single dependency unit."""

    name: str
    type: str
    current_load_state: Optional[str] = None
    current_active_state: Optional[str] = None
    current_sub_state: Optional[str] = None
    is_problematic: bool = False


@dataclass
class FailedUnitDependencyInfo:
    """Stores dependency analysis results for a single failed unit."""

    unit_name: str
    dependencies: List[DependencyInfo] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class DependencyAnalysisResult:
    """Aggregates all dependency analysis findings for failed units."""

    failed_unit_dependencies: List[FailedUnitDependencyInfo] = field(
        default_factory=list
    )
    analysis_error: Optional[str] = None


# --- Full Dependency Graph Analysis Data Structures ---


@dataclass
class FullDependencyAnalysisResult:
    """Aggregates results from full dependency graph analysis."""

    detected_cycles: List[List[str]] = field(default_factory=list)
    analysis_error: Optional[str] = None
    dependency_fetch_error: Optional[str] = None
    graph_build_error: Optional[str] = None


# --- ML Analysis Data Structures ---


@dataclass
class AnomalyInfo:
    """Stores information about a detected anomaly for a unit."""

    unit_name: str
    score: float


@dataclass
class MLAnalysisResult:
    """Aggregates results from ML analysis."""

    anomalies_detected: List[AnomalyInfo] = field(default_factory=list)
    models_loaded_count: int = 0
    units_analyzed_count: int = 0
    skipped_zero_variance_units: List[str] = field(default_factory=list)
    error: Optional[str] = None


# --- LLM Analysis Data Structures ---
@dataclass
class LLMAnalysisResult:
    """Aggregates results from LLM analysis."""

    synthesis: Optional[str] = None
    prompt_token_count: Optional[int] = None
    completion_token_count: Optional[int] = None
    model_used: Optional[str] = None
    provider_used: Optional[str] = None
    error: Optional[str] = None


# --- eBPF Analysis Data Structures ---
@dataclass
class EBPFBaseEvent:
    """Base class for eBPF events."""

    timestamp_ns: int
    pid: int
    ppid: int
    comm: str
    cgroup_id: Optional[int]  # Type hint added


@dataclass
class EBPFExecEvent(EBPFBaseEvent):
    """Stores information about a process execution event."""

    filename: str
    argv: List[str] = field(default_factory=list)


@dataclass
class EBPFExitEvent(EBPFBaseEvent):
    """Stores information about a process exit event."""

    exit_code: int


@dataclass
class EBPFAnalysisResult:
    """Aggregates results from eBPF analysis."""

    exec_events: List[EBPFExecEvent] = field(default_factory=list)
    exit_events: List[EBPFExitEvent] = field(default_factory=list)
    units_with_execs: Dict[str, int] = field(default_factory=dict)
    units_with_exits: Dict[str, int] = field(default_factory=dict)
    error: Optional[str] = None


# --- Single Unit Analysis ---
@dataclass
class SingleUnitReport:
    """Structure for the focused analysis of a single unit."""

    unit_info: Optional[UnitHealthInfo] = None
    resource_usage: Optional[UnitResourceUsage] = None
    dependency_info: Optional[FailedUnitDependencyInfo] = None
    analysis_error: Optional[str] = None


# --- Full System Report ---


@dataclass
class SystemReport:
    """Top-level structure for the entire analysis report."""

    hostname: Optional[str] = None
    timestamp: Optional[str] = None
    boot_id: Optional[str] = None
    boot_analysis: Optional[BootAnalysisResult] = None
    health_analysis: Optional[HealthAnalysisResult] = None
    resource_analysis: Optional[ResourceAnalysisResult] = None
    log_analysis: Optional[LogAnalysisResult] = None
    dependency_analysis: Optional[DependencyAnalysisResult] = None
    full_dependency_analysis: Optional[FullDependencyAnalysisResult] = None
    ml_analysis: Optional[MLAnalysisResult] = None
    llm_analysis: Optional[LLMAnalysisResult] = None
    ebpf_analysis: Optional[EBPFAnalysisResult] = None
    errors: List[str] = field(default_factory=list)
