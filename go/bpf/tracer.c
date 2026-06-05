//go:build ignore
// CO-RE eBPF: per-cgroup process-failure forensics. Everything is aggregated
// in-kernel (keyed by cgroup id) so userspace just reads maps periodically,
// rather than streaming every event. Captures, per cgroup: exec/exit counts,
// abnormal terminations (split into signal-killed vs nonzero-exit), OOM kills,
// fatal signals (SIGKILL/SIGTERM) delivered to members, and the most-executed
// binary. Compiled at build time by bpf2go (clang).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16

// Per-cgroup aggregated stats (read by userspace at the end of the window).
struct proc_stat {
	__u64 execs;
	__u64 exits;
	__u64 exit_nonzero;   // exited with a nonzero status code
	__u64 exit_signaled;  // terminated by a signal
	__u64 oom_kills;      // killed by the OOM killer
	__u64 sigkill_rcvd;   // SIGKILL delivered to a member
	__u64 sigterm_rcvd;   // SIGTERM delivered to a member
	__u64 offcpu_ns;      // time members spent off-CPU in uninterruptible (D) sleep
	__u32 last_signal;    // most recent fatal signal number
	__u32 last_exit_code; // most recent nonzero exit code
};

#define TASK_UNINTERRUPTIBLE 0x0002

// Key for the top-binary map: (cgroup, comm) -> exec count.
struct exec_key {
	__u64 cgid;
	char  comm[TASK_COMM_LEN];
};

// Per-pid off-CPU start record (D-state enter), resolved on the next wake-up.
struct offcpu_start {
	__u64 ts;
	__u64 cgid;
};

// Force BTF emission so bpf2go can generate Go structs (-type).
struct proc_stat *_unused_proc_stat __attribute__((unused));
struct exec_key *_unused_exec_key __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct proc_stat);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct exec_key);
	__type(value, __u64);
} exec_names SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct offcpu_start);
} offcpu SEC(".maps");

// kfuncs (kernel >= 5.18/6.x) to resolve a pid to its task, so OOM/signal
// events (which fire in the killer's context) can be attributed to the victim.
extern struct task_struct *bpf_task_from_pid(__s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

static __always_inline struct proc_stat *stat_for(__u64 cgid)
{
	struct proc_stat *s = bpf_map_lookup_elem(&stats, &cgid);
	if (s)
		return s;
	struct proc_stat zero = {};
	bpf_map_update_elem(&stats, &cgid, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(&stats, &cgid);
}

// cgroup id of an arbitrary task (matches bpf_get_current_cgroup_id semantics).
static __always_inline __u64 task_cgid(struct task_struct *t)
{
	return BPF_CORE_READ(t, cgroups, dfl_cgrp, kn, id);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(void *ctx)
{
	__u64 cgid = bpf_get_current_cgroup_id();
	struct proc_stat *s = stat_for(cgid);
	if (s)
		__sync_fetch_and_add(&s->execs, 1);

	struct exec_key k = {};
	k.cgid = cgid;
	bpf_get_current_comm(&k.comm, sizeof(k.comm));
	__u64 *c = bpf_map_lookup_elem(&exec_names, &k);
	if (c) {
		__sync_fetch_and_add(c, 1);
	} else {
		__u64 one = 1;
		bpf_map_update_elem(&exec_names, &k, &one, BPF_ANY);
	}
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(void *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	// Count process (thread-group leader) exits only.
	if (BPF_CORE_READ(task, pid) != BPF_CORE_READ(task, tgid))
		return 0;
	__u64 cgid = bpf_get_current_cgroup_id();
	struct proc_stat *s = stat_for(cgid);
	if (!s)
		return 0;
	__sync_fetch_and_add(&s->exits, 1);

	int code = BPF_CORE_READ(task, exit_code); // raw wait status
	int sig = code & 0x7f;
	int ec = (code >> 8) & 0xff;
	if (sig != 0 && sig != 0x7f) {
		__sync_fetch_and_add(&s->exit_signaled, 1);
		s->last_signal = sig;
	} else if (ec != 0) {
		__sync_fetch_and_add(&s->exit_nonzero, 1);
		s->last_exit_code = ec;
	}
	return 0;
}

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
	__u64 now = bpf_ktime_get_ns();
	__u32 prev_pid = BPF_CORE_READ(ctx, prev_pid);
	long prev_state = BPF_CORE_READ(ctx, prev_state);
	__u32 next_pid = BPF_CORE_READ(ctx, next_pid);

	// Task going off-CPU in uninterruptible (D) sleep: stamp its start.
	// At this tracepoint `current` is still prev, so its cgroup id is correct.
	if ((prev_state & TASK_UNINTERRUPTIBLE) && prev_pid != 0) {
		struct offcpu_start s = {};
		s.ts = now;
		s.cgid = bpf_get_current_cgroup_id();
		bpf_map_update_elem(&offcpu, &prev_pid, &s, BPF_ANY);
	}
	// Task returning to CPU: attribute the D-state stall to its cgroup.
	struct offcpu_start *st = bpf_map_lookup_elem(&offcpu, &next_pid);
	if (st) {
		__u64 delta = now - st->ts;
		struct proc_stat *ps = stat_for(st->cgid);
		if (ps)
			__sync_fetch_and_add(&ps->offcpu_ns, delta);
		bpf_map_delete_elem(&offcpu, &next_pid);
	}
	return 0;
}

SEC("tracepoint/oom/mark_victim")
int handle_oom(struct trace_event_raw_mark_victim *ctx)
{
	__s32 pid = BPF_CORE_READ(ctx, pid);
	struct task_struct *t = bpf_task_from_pid(pid);
	if (!t)
		return 0;
	__u64 cgid = task_cgid(t);
	bpf_task_release(t);
	struct proc_stat *s = stat_for(cgid);
	if (s)
		__sync_fetch_and_add(&s->oom_kills, 1);
	return 0;
}

SEC("tracepoint/signal/signal_generate")
int handle_signal(struct trace_event_raw_signal_generate *ctx)
{
	int sig = BPF_CORE_READ(ctx, sig);
	if (sig != 9 && sig != 15) // SIGKILL, SIGTERM
		return 0;
	__s32 pid = BPF_CORE_READ(ctx, pid);
	struct task_struct *t = bpf_task_from_pid(pid);
	if (!t)
		return 0;
	__u64 cgid = task_cgid(t);
	bpf_task_release(t);
	struct proc_stat *s = stat_for(cgid);
	if (!s)
		return 0;
	if (sig == 9)
		__sync_fetch_and_add(&s->sigkill_rcvd, 1);
	else
		__sync_fetch_and_add(&s->sigterm_rcvd, 1);
	return 0;
}
