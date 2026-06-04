//go:build ignore
// CO-RE eBPF program: traces process exec and exit, emitting events to a ring
// buffer with the owning cgroup id. Compiled at build time by bpf2go (clang).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define FILENAME_LEN 256

// Must match the Go-side decode (bpf2go generates tracerEvent from this).
struct event {
	__u64 ts_ns;
	__u32 pid;
	__u32 ppid;
	__u64 cgroup_id;
	__s32 exit_code;
	__u8  kind; // 0 = exec, 1 = exit
	char  comm[TASK_COMM_LEN];
	char  filename[FILENAME_LEN];
};
// Force struct emission into BTF for -type event.
struct event *_unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 id = bpf_get_current_pid_tgid();
	e->ts_ns = bpf_ktime_get_ns();
	e->pid = id >> 32; // upper 32 bits = TGID = userspace PID
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->exit_code = 0;
	e->kind = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	const char *fn = (const char *)BPF_CORE_READ(ctx, args[0]);
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), fn);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(void *ctx)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 id = bpf_get_current_pid_tgid();
	e->ts_ns = bpf_ktime_get_ns();
	e->pid = id >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->exit_code = BPF_CORE_READ(task, exit_code) >> 8;
	e->kind = 1;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->filename[0] = 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}
