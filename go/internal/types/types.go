// Package types defines the report data model. JSON tags mirror the Python
// dataclasses (snake_case) so reports and exporter metrics stay compatible.
package types

// SystemResourceUsage mirrors datatypes.SystemResourceUsage.
type SystemResourceUsage struct {
	CPUPercent       *float64 `json:"cpu_percent"`
	MemTotalBytes    *int64   `json:"mem_total_bytes"`
	MemAvailBytes    *int64   `json:"mem_available_bytes"`
	MemPercent       *float64 `json:"mem_percent"`
	SwapTotalBytes   *int64   `json:"swap_total_bytes"`
	SwapUsedBytes    *int64   `json:"swap_used_bytes"`
	SwapPercent      *float64 `json:"swap_percent"`
	DiskIOReadBytes  *int64   `json:"disk_io_read_bytes"`
	DiskIOWriteBytes *int64   `json:"disk_io_write_bytes"`
	NetIOSentBytes   *int64   `json:"net_io_sent_bytes"`
	NetIORecvBytes   *int64   `json:"net_io_recv_bytes"`
	Error            string   `json:"error,omitempty"`
}

// UnitResourceUsage mirrors datatypes.UnitResourceUsage.
type UnitResourceUsage struct {
	Name              string `json:"name"`
	CgroupPath        string `json:"cgroup_path,omitempty"`
	CPUUsageNsec      *int64 `json:"cpu_usage_nsec"`
	MemoryCurrentByte *int64 `json:"memory_current_bytes"`
	MemoryPeakBytes   *int64 `json:"memory_peak_bytes"`
	MemoryMaxBytes    *int64 `json:"memory_max_bytes"`  // nil = "max"/unlimited
	MemoryHighBytes   *int64 `json:"memory_high_bytes"` // nil = "max"/unset
	MemoryAnonBytes   *int64 `json:"memory_anon_bytes"`
	MemoryFileBytes   *int64 `json:"memory_file_bytes"`
	IOReadBytes       *int64 `json:"io_read_bytes"`
	IOWriteBytes      *int64 `json:"io_write_bytes"`
	TasksCurrent      *int64 `json:"tasks_current"`
	Error             string `json:"error,omitempty"`
}

// MemoryPercentOfLimit returns current memory as a % of the hard limit, or nil
// when there is no usage reading or no finite limit (mirrors the Python property,
// which is not serialized).
func (u *UnitResourceUsage) MemoryPercentOfLimit() *float64 {
	if u.MemoryCurrentByte == nil || u.MemoryMaxBytes == nil || *u.MemoryMaxBytes == 0 {
		return nil
	}
	v := float64(*u.MemoryCurrentByte) / float64(*u.MemoryMaxBytes) * 100.0
	return &v
}

// ChildProcessGroupUsage mirrors datatypes.ChildProcessGroupUsage.
type ChildProcessGroupUsage struct {
	CommandName             string   `json:"command_name"`
	ParentUnit              string   `json:"parent_unit"`
	ProcessCount            int      `json:"process_count"`
	Pids                    []int    `json:"pids"`
	AggregatedCPUSecondsTot *float64 `json:"aggregated_cpu_seconds_total"`
	AggregatedMemoryBytes   *int64   `json:"aggregated_memory_bytes"`
}

// ResourceAnalysisResult mirrors datatypes.ResourceAnalysisResult.
type ResourceAnalysisResult struct {
	SystemUsage        *SystemResourceUsage     `json:"system_usage"`
	UnitUsage          []UnitResourceUsage      `json:"unit_usage"`
	ChildProcessGroups []ChildProcessGroupUsage `json:"child_process_groups"`
	TopCPUUnits        []UnitResourceUsage      `json:"top_cpu_units"`
	TopMemoryUnits     []UnitResourceUsage      `json:"top_memory_units"`
	TopIOUnits         []UnitResourceUsage      `json:"top_io_units"`
	AnalysisError      string                   `json:"analysis_error,omitempty"`
}

// UnitHealthInfo mirrors datatypes.UnitHealthInfo.
type UnitHealthInfo struct {
	Name                string            `json:"name"`
	LoadState           string            `json:"load_state,omitempty"`
	ActiveState         string            `json:"active_state,omitempty"`
	SubState            string            `json:"sub_state,omitempty"`
	Description         string            `json:"description,omitempty"`
	Path                string            `json:"path,omitempty"`
	IsFailed            bool              `json:"is_failed"`
	IsFlapping          bool              `json:"is_flapping"`
	IsProblematicSocket bool              `json:"is_problematic_socket"`
	IsProblematicTimer  bool              `json:"is_problematic_timer"`
	Details             map[string]string `json:"details,omitempty"`
	RecentLogs          []string          `json:"recent_logs,omitempty"`
	ErrorMessage        string            `json:"error_message,omitempty"`
}

// HealthAnalysisResult mirrors datatypes.HealthAnalysisResult.
type HealthAnalysisResult struct {
	FailedUnits        []UnitHealthInfo `json:"failed_units"`
	FlappingUnits      []UnitHealthInfo `json:"flapping_units"`
	ProblematicSockets []UnitHealthInfo `json:"problematic_sockets"`
	ProblematicTimers  []UnitHealthInfo `json:"problematic_timers"`
	AllUnitsCount      int              `json:"all_units_count"`
	AnalysisError      string           `json:"analysis_error,omitempty"`
}

// --- Boot ---

type BootTimes struct {
	Firmware  string `json:"firmware,omitempty"`
	Loader    string `json:"loader,omitempty"`
	Kernel    string `json:"kernel,omitempty"`
	Initrd    string `json:"initrd,omitempty"`
	Userspace string `json:"userspace,omitempty"`
	Total     string `json:"total,omitempty"`
	Error     string `json:"error,omitempty"`
}

type BootBlameItem struct {
	Time string `json:"time"`
	Unit string `json:"unit"`
}

type CriticalChainItem struct {
	Unit      string `json:"unit"`
	TimeAt    string `json:"time_at,omitempty"`
	TimeDelta string `json:"time_delta,omitempty"`
	Indent    int    `json:"indent"`
}

type BootAnalysisResult struct {
	Times              *BootTimes          `json:"times"`
	Blame              []BootBlameItem     `json:"blame"`
	CriticalChain      []CriticalChainItem `json:"critical_chain"`
	BlameError         string              `json:"blame_error,omitempty"`
	CriticalChainError string              `json:"critical_chain_error,omitempty"`
}

// --- Logs ---

type LogPatternInfo struct {
	PatternType     string   `json:"pattern_type"`
	PatternKey      string   `json:"pattern_key"`
	Count           int      `json:"count"`
	Level           string   `json:"level,omitempty"`
	ExampleMessages []string `json:"example_messages"`
}

type LogAnalysisResult struct {
	DetectedPatterns     []LogPatternInfo `json:"detected_patterns"`
	TotalEntriesAnalyzed int              `json:"total_entries_analyzed"`
	LogSource            string           `json:"log_source,omitempty"`
	AnalysisError        string           `json:"analysis_error,omitempty"`
}

// --- Dependencies ---

type DependencyInfo struct {
	Name               string `json:"name"`
	Type               string `json:"type"`
	CurrentLoadState   string `json:"current_load_state,omitempty"`
	CurrentActiveState string `json:"current_active_state,omitempty"`
	CurrentSubState    string `json:"current_sub_state,omitempty"`
	IsProblematic      bool   `json:"is_problematic"`
}

type FailedUnitDependencyInfo struct {
	UnitName     string           `json:"unit_name"`
	Dependencies []DependencyInfo `json:"dependencies"`
	Error        string           `json:"error,omitempty"`
}

type DependencyAnalysisResult struct {
	FailedUnitDependencies []FailedUnitDependencyInfo `json:"failed_unit_dependencies"`
	AnalysisError          string                     `json:"analysis_error,omitempty"`
}

type FullDependencyAnalysisResult struct {
	DetectedCycles       [][]string `json:"detected_cycles"`
	AnalysisError        string     `json:"analysis_error,omitempty"`
	DependencyFetchError string     `json:"dependency_fetch_error,omitempty"`
	GraphBuildError      string     `json:"graph_build_error,omitempty"`
}

// --- ML / memory-leak ---

type AnomalyInfo struct {
	UnitName            string             `json:"unit_name"`
	Score               float64            `json:"score"`
	Method              string             `json:"method,omitempty"`
	ContributingMetrics map[string]float64 `json:"contributing_metrics,omitempty"`
}

type MLAnalysisResult struct {
	AnomaliesDetected        []AnomalyInfo `json:"anomalies_detected"`
	ModelsLoadedCount        int           `json:"models_loaded_count"`
	UnitsAnalyzedCount       int           `json:"units_analyzed_count"`
	SkippedZeroVarianceUnits []string      `json:"skipped_zero_variance_units"`
	Error                    string        `json:"error,omitempty"`
}

type MemoryLeakInfo struct {
	UnitName          string  `json:"unit_name"`
	SlopeBytesPerHour float64 `json:"slope_bytes_per_hour"`
	GrowthBytes       int64   `json:"growth_bytes"`
	RSquared          float64 `json:"r_squared"`
	Samples           int     `json:"samples"`
}

type MemoryLeakAnalysisResult struct {
	SuspectedLeaks     []MemoryLeakInfo `json:"suspected_leaks"`
	UnitsAnalyzedCount int              `json:"units_analyzed_count"`
	Error              string           `json:"error,omitempty"`
}

// --- LLM ---

type LLMAnalysisResult struct {
	Synthesis            string `json:"synthesis,omitempty"`
	PromptTokenCount     *int   `json:"prompt_token_count"`
	CompletionTokenCount *int   `json:"completion_token_count"`
	ModelUsed            string `json:"model_used,omitempty"`
	ProviderUsed         string `json:"provider_used,omitempty"`
	Error                string `json:"error,omitempty"`
}

// --- eBPF ---

type EBPFExecEvent struct {
	TimestampNs uint64   `json:"timestamp_ns"`
	Pid         uint32   `json:"pid"`
	Ppid        uint32   `json:"ppid"`
	Comm        string   `json:"comm"`
	CgroupID    uint64   `json:"cgroup_id"`
	Filename    string   `json:"filename"`
	Argv        []string `json:"argv"`
}

type EBPFExitEvent struct {
	TimestampNs uint64 `json:"timestamp_ns"`
	Pid         uint32 `json:"pid"`
	Ppid        uint32 `json:"ppid"`
	Comm        string `json:"comm"`
	CgroupID    uint64 `json:"cgroup_id"`
	ExitCode    int32  `json:"exit_code"`
}

type EBPFAnalysisResult struct {
	ExecEvents     []EBPFExecEvent `json:"exec_events"`
	ExitEvents     []EBPFExitEvent `json:"exit_events"`
	UnitsWithExecs map[string]int  `json:"units_with_execs"`
	UnitsWithExits map[string]int  `json:"units_with_exits"`
	Error          string          `json:"error,omitempty"`
}

// SystemReport mirrors datatypes.SystemReport.
type SystemReport struct {
	Hostname               string                        `json:"hostname"`
	Timestamp              string                        `json:"timestamp"`
	BootID                 string                        `json:"boot_id"`
	BootAnalysis           *BootAnalysisResult           `json:"boot_analysis,omitempty"`
	HealthAnalysis         *HealthAnalysisResult         `json:"health_analysis,omitempty"`
	ResourceAnalysis       *ResourceAnalysisResult       `json:"resource_analysis,omitempty"`
	LogAnalysis            *LogAnalysisResult            `json:"log_analysis,omitempty"`
	DependencyAnalysis     *DependencyAnalysisResult     `json:"dependency_analysis,omitempty"`
	FullDependencyAnalysis *FullDependencyAnalysisResult `json:"full_dependency_analysis,omitempty"`
	MLAnalysis             *MLAnalysisResult             `json:"ml_analysis,omitempty"`
	MemoryLeakAnalysis     *MemoryLeakAnalysisResult     `json:"memory_leak_analysis,omitempty"`
	LLMAnalysis            *LLMAnalysisResult            `json:"llm_analysis,omitempty"`
	EBPFAnalysis           *EBPFAnalysisResult           `json:"ebpf_analysis,omitempty"`
	Errors                 []string                      `json:"errors"`
}

// SingleUnitReport mirrors datatypes.SingleUnitReport (analyze-unit output).
type SingleUnitReport struct {
	UnitInfo       *UnitHealthInfo           `json:"unit_info,omitempty"`
	ResourceUsage  *UnitResourceUsage        `json:"resource_usage,omitempty"`
	DependencyInfo *FailedUnitDependencyInfo `json:"dependency_info,omitempty"`
	AnalysisError  string                    `json:"analysis_error,omitempty"`
}
