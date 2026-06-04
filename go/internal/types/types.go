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
	ParentUnit              string   `json:"parent_unit"`
	CommandName             string   `json:"command_name"`
	ProcessCount            int      `json:"process_count"`
	AggregatedMemoryBytes   *int64   `json:"aggregated_memory_bytes"`
	AggregatedCPUSecondsTot *float64 `json:"aggregated_cpu_seconds_total"`
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
	FailedUnits         []UnitHealthInfo `json:"failed_units"`
	FlappingUnits       []UnitHealthInfo `json:"flapping_units"`
	ProblematicSockets  []UnitHealthInfo `json:"problematic_sockets"`
	ProblematicTimers   []UnitHealthInfo `json:"problematic_timers"`
	AllUnitsCount       int              `json:"all_units_count"`
	AnalysisError       string           `json:"analysis_error,omitempty"`
}

// SystemReport mirrors datatypes.SystemReport (subset populated so far).
type SystemReport struct {
	Hostname         string                  `json:"hostname"`
	Timestamp        string                  `json:"timestamp"`
	BootID           string                  `json:"boot_id"`
	HealthAnalysis   *HealthAnalysisResult   `json:"health_analysis,omitempty"`
	ResourceAnalysis *ResourceAnalysisResult `json:"resource_analysis,omitempty"`
	Errors           []string                `json:"errors"`
}
