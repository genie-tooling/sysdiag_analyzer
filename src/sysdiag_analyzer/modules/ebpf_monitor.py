# -*- coding: utf-8 -*-

import logging
import time
import ctypes as ct
from typing import List, Optional

# Conditional BCC import
try:
    from bcc import BPF # type: ignore
    from bcc.utils import printb # type: ignore
    HAS_BCC = True
except ImportError as e:
    HAS_BCC = False
    BPF = None # type: ignore
    printb = lambda x: print(x) # Dummy printb  # noqa: E731
    print(f"BCC import error: {e}")

from ..datatypes import EBPFAnalysisResult, EBPFExecEvent, EBPFExitEvent

log = logging.getLogger(__name__)
log_ebpf = logging.getLogger(__name__ + ".ebpf_detail") # Specific logger for eBPF details

# --- BPF Program ---
# Simple program to trace execve and process exits
# Includes cgroup ID capture
BPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

// Event structure for execve
struct exec_data_t {
    u64 timestamp_ns;
    u32 pid;
    u32 ppid;
    u64 cgroup_id;
    char comm[TASK_COMM_LEN];
    char filename[NAME_MAX];
    // We could add argv here, but it requires more complex handling (BPF_PERF_OUTPUT size limits)
};
BPF_PERF_OUTPUT(exec_events);

// Event structure for exit
struct exit_data_t {
    u64 timestamp_ns;
    u32 pid;
    u32 ppid;
    u64 cgroup_id;
    char comm[TASK_COMM_LEN];
    int exit_code;
};
BPF_PERF_OUTPUT(exit_events);

// Using tracepoint for process execution for reliability
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    data.timestamp_ns = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32; // PID is upper 32 bits
    data.ppid = task->real_parent->tgid;
    data.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Read filename argument
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)args->filename);

    exec_events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// Using tracepoint for process exit
TRACEPOINT_PROBE(sched, sched_process_exit) {
    struct exit_data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    data.timestamp_ns = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;
    // Parent PID might be less reliable at exit, but let's try
    // If task->real_parent is NULL, ppid will be 0
    data.ppid = task->real_parent ? task->real_parent->tgid : 0;
    data.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Extract exit code (might be encoded, needs check)
    // The exit code is in task->exit_code, but accessing it directly might be tricky/unstable.
    // The tracepoint args might expose it more reliably if available.
    // For simplicity, let's use a placeholder for now.
    data.exit_code = task->exit_code >> 8; // Simplified extraction, might need refinement

    exit_events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

# --- Python Event Structures (matching BPF structs) ---
# Define corresponding ctypes structures for parsing perf buffer data

class ExecData(ct.Structure):
    _fields_ = [
        ("timestamp_ns", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("ppid", ct.c_uint),
        ("cgroup_id", ct.c_ulonglong),
        ("comm", ct.c_char * 16), # TASK_COMM_LEN
        ("filename", ct.c_char * 255), # NAME_MAX approximation
    ]

class ExitData(ct.Structure):
    _fields_ = [
        ("timestamp_ns", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("ppid", ct.c_uint),
        ("cgroup_id", ct.c_ulonglong),
        ("comm", ct.c_char * 16),
        ("exit_code", ct.c_int),
    ]


# --- eBPF Collector Class ---

class EBPFCollector:
    """Manages BPF program loading, event collection, and processing."""

    def __init__(self):
        if not HAS_BCC or not BPF:
            raise ImportError("BCC library is not available.")
        self.bpf: Optional[BPF] = None
        self.exec_events: List[EBPFExecEvent] = []
        self.exit_events: List[EBPFExitEvent] = []
        self._running = False

    def _handle_exec_event(self, cpu, data, size):
        """Callback for handling exec events from perf buffer."""
        try:
            event = ct.cast(data, ct.POINTER(ExecData)).contents
            self.exec_events.append(EBPFExecEvent(
                timestamp_ns=event.timestamp_ns,
                pid=event.pid,
                ppid=event.ppid,
                cgroup_id=event.cgroup_id,
                comm=event.comm.decode('utf-8', 'replace'),
                filename=event.filename.decode('utf-8', 'replace'),
                # Argv parsing omitted for simplicity
            ))
            if log_ebpf.isEnabledFor(logging.DEBUG):
                 log_ebpf.debug(f"eBPF EXEC Event: PID={event.pid}, PPID={event.ppid}, CG={event.cgroup_id}, COMM={event.comm.decode()}, FILE={event.filename.decode()}")
        except Exception as e:
            log_ebpf.error(f"Error processing eBPF exec event: {e}")

    def _handle_exit_event(self, cpu, data, size):
        """Callback for handling exit events from perf buffer."""
        try:
            event = ct.cast(data, ct.POINTER(ExitData)).contents
            self.exit_events.append(EBPFExitEvent(
                timestamp_ns=event.timestamp_ns,
                pid=event.pid,
                ppid=event.ppid,
                cgroup_id=event.cgroup_id,
                comm=event.comm.decode('utf-8', 'replace'),
                exit_code=event.exit_code,
            ))
            if log_ebpf.isEnabledFor(logging.DEBUG):
                 log_ebpf.debug(f"eBPF EXIT Event: PID={event.pid}, PPID={event.ppid}, CG={event.cgroup_id}, COMM={event.comm.decode()}, CODE={event.exit_code}")
        except Exception as e:
            log_ebpf.error(f"Error processing eBPF exit event: {e}")

    def start(self):
        """Load BPF program and open perf buffers."""
        if self._running:
            log.warning("eBPF collector already running.")
            return
        log.info("Loading eBPF program...")
        try:
            self.bpf = BPF(text=BPF_PROGRAM)
            log.info("eBPF program loaded successfully.")

            log.info("Opening eBPF perf buffers...")
            self.bpf["exec_events"].open_perf_buffer(self._handle_exec_event)
            self.bpf["exit_events"].open_perf_buffer(self._handle_exit_event)
            log.info("eBPF perf buffers opened.")
            self._running = True
        except Exception as e:
            log.exception("Failed to initialize BPF program or open perf buffers.")
            self.bpf = None # Ensure bpf is None if init fails
            raise RuntimeError(f"eBPF initialization failed: {e}")

    def poll_events(self, timeout_ms: int = 100):
        """Polls the perf buffers for new events."""
        if not self._running or not self.bpf:
            log.warning("Cannot poll events, eBPF collector not running.")
            return
        try:
            self.bpf.perf_buffer_poll(timeout=timeout_ms)
        except Exception as e:
            log.error(f"Error during perf_buffer_poll: {e}")
            # Consider stopping or handling the error more robustly

    def stop(self) -> EBPFAnalysisResult:
        """Stop monitoring, close buffers, and return collected data."""
        log.info("Stopping eBPF monitoring...")
        self._running = False
        result = EBPFAnalysisResult()

        # Poll one last time to catch any remaining events
        if self.bpf:
            try:
                self.poll_events(timeout_ms=200) # Longer timeout on stop
            except Exception as e:
                 log.warning(f"Error during final poll_events on stop: {e}")

        # Detach probes and cleanup BPF resources
        if self.bpf:
            try:
                self.bpf.cleanup()
                log.info("eBPF resources cleaned up.")
            except Exception as e:
                 log.error(f"Error during BPF cleanup: {e}")
                 result.error = f"BPF cleanup error: {e}"

        self.bpf = None
        result.exec_events = self.exec_events
        result.exit_events = self.exit_events
        # TODO: Add aggregation logic here (e.g., count events per cgroup/unit)
        log.info(f"eBPF monitoring stopped. Collected {len(result.exec_events)} execs, {len(result.exit_events)} exits.")
        return result

# --- Module Level Function (Optional Simplification) ---
# This could be used by main.py if managing the collector instance is too complex there.

def run_ebpf_analysis(duration_sec: int = 5) -> EBPFAnalysisResult:
    """Runs eBPF monitoring for a short duration and returns results."""
    if not HAS_BCC:
        return EBPFAnalysisResult(error="'bcc' library not installed.")

    collector = None
    try:
        collector = EBPFCollector()
        collector.start()
        log.info(f"eBPF monitoring active for {duration_sec} seconds...")
        # Poll periodically during the analysis window
        end_time = time.time() + duration_sec
        while time.time() < end_time:
            collector.poll_events(timeout_ms=100)
            time.sleep(0.1) # Avoid busy-waiting
        log.info("eBPF analysis duration finished.")
        return collector.stop()
    except Exception as e:
        log.exception(f"Error during eBPF analysis run: {e}")
        if collector and collector._running:
             # Attempt to stop cleanly even if error occurred during polling
             try:
                  return collector.stop()
             except Exception as stop_e:
                  log.error(f"Error stopping collector after run failure: {stop_e}")
        return EBPFAnalysisResult(error=f"eBPF run failed: {e}")

