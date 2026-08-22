// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ARGS 20
#define MAX_ARG_LEN 256

struct argv_cache {
    char filename[MAX_ARG_LEN];
    __u32 argc;
    char argv[MAX_ARGS][MAX_ARG_LEN];
};

struct exec_event {
    __u64 ts_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 tid;
    __u32 tgid;
    __u32 old_pid;
    __u64 task_start_kernel_ns;
    __u64 first_observed_kernel_ns;
    char comm[16];
    char filename[MAX_ARG_LEN];
    __u32 argc;
    char argv[MAX_ARGS][MAX_ARG_LEN];
};

enum process_event_kind {
    PROCESS_FORK = 1,
    PROCESS_EXIT = 2,
    PROCESS_EXEC_REKEY = 3,
};

struct process_event {
    __u64 ts_ns;
    __u64 cgroup_id;
    __u64 task_start_kernel_ns;
    __u64 parent_task_start_kernel_ns;
    __u64 first_observed_kernel_ns;
    __u32 kind;
    __u32 tid;
    __u32 tgid;
    __u32 parent_tid;
    __u32 parent_tgid;
    __u32 child_tid;
    __u32 child_tgid;
    __u32 old_pid;
};

struct trace_event_raw_sched_process_fork {
    __u64 unused;
    char parent_comm[16];
    __s32 parent_pid;
    char child_comm[16];
    __s32 child_pid;
};

struct trace_event_raw_sched_process_exec {
    __u64 unused;
    __u32 filename;
    __s32 pid;
    __s32 old_pid;
};

struct trace_event_raw_sys_enter {
    __u64 unused;
    long id;
    unsigned long args[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct argv_cache);
} argv_cache_map SEC(".maps");

/* Scratch buffer to avoid large on-stack allocations (BPF stack is small). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct argv_cache);
} scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} process_events SEC(".maps");

/* A value exists only for tasks forked after the tracer was attached. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} task_start_map SEC(".maps");

/* First lifecycle event for tasks that predate tracer attachment. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} first_observed_map SEC(".maps");

static __always_inline __u64 task_start(__u32 tid) {
    __u64 *start = bpf_map_lookup_elem(&task_start_map, &tid);
    return start ? *start : 0;
}

static __always_inline __u64 first_observed(__u32 tid, __u64 now) {
    __u64 *seen = bpf_map_lookup_elem(&first_observed_map, &tid);
    if (seen) {
        return *seen;
    }
    bpf_map_update_elem(&first_observed_map, &tid, &now, BPF_ANY);
    return now;
}

static __always_inline void submit_process_event(__u32 kind, __u32 tid, __u32 tgid,
                                                  __u32 parent_tid, __u32 parent_tgid,
                                                  __u32 child_tid, __u32 child_tgid,
                                                  __u32 old_pid, __u64 start_ns,
                                                  __u64 parent_start_ns,
                                                  __u64 first_observed_ns) {
    struct process_event *event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event) {
        return;
    }
    event->ts_ns = bpf_ktime_get_ns();
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->task_start_kernel_ns = start_ns;
    event->parent_task_start_kernel_ns = parent_start_ns;
    event->first_observed_kernel_ns = first_observed_ns;
    event->kind = kind;
    event->tid = tid;
    event->tgid = tgid;
    event->parent_tid = parent_tid;
    event->parent_tgid = parent_tgid;
    event->child_tid = child_tid;
    event->child_tgid = child_tgid;
    event->old_pid = old_pid;
    bpf_ringbuf_submit(event, 0);
}

static __always_inline int read_exec_data(__u32 pid, const char *filename, const char *const *argv) {
    __u32 k = 0;
    struct argv_cache *cache = bpf_map_lookup_elem(&scratch, &k);
    if (!cache) {
        return 0;
    }

    if (filename) {
        bpf_probe_read_user_str(cache->filename, sizeof(cache->filename), filename);
    } else {
        cache->filename[0] = 0;
    }
    cache->argc = 0;

#pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = 0;
        cache->argv[i][0] = 0;
        if (!argv) {
            break;
        }
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) < 0) {
            break;
        }
        if (!argp) {
            break;
        }
        if (bpf_probe_read_user_str(cache->argv[i], MAX_ARG_LEN, argp) <= 0) {
            break;
        }
        cache->argc++;
    }

    bpf_map_update_elem(&argv_cache_map, &pid, cache, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    const char *filename = (const char *)ctx->args[0];
    const char *const *argv = (const char *const *)ctx->args[1];
    return read_exec_data(pid, filename, argv);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_enter_execveat(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    const char *filename = (const char *)ctx->args[1];
    const char *const *argv = (const char *const *)ctx->args[2];
    return read_exec_data(pid, filename, argv);
}

SEC("tracepoint/sched/sched_process_exec")
int trace_sched_exec(struct trace_event_raw_sched_process_exec *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u32 pid = (__u32)ctx->pid;
    __u32 old_pid = (__u32)ctx->old_pid;
    __u32 uid = (__u32)bpf_get_current_uid_gid();
    __u64 now = bpf_ktime_get_ns();
    __u64 start_ns = task_start(old_pid);
    if (!start_ns) {
        start_ns = task_start(pid);
    }
	__u64 first_observed_ns = start_ns ? 0 : first_observed(old_pid, now);

    if (old_pid != pid) {
        if (start_ns) {
            bpf_map_update_elem(&task_start_map, &pid, &start_ns, BPF_ANY);
        } else {
            bpf_map_update_elem(&first_observed_map, &pid, &first_observed_ns, BPF_ANY);
        }
        bpf_map_delete_elem(&task_start_map, &old_pid);
        bpf_map_delete_elem(&first_observed_map, &old_pid);
        submit_process_event(PROCESS_EXEC_REKEY, pid, tgid, 0, 0, 0, 0,
                             old_pid, start_ns, 0, first_observed_ns);
    }

    struct exec_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&argv_cache_map, &pid);
        return 0;
    }

    event->ts_ns = now;
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->pid = pid;
    event->ppid = 0;
    event->uid = uid;
    event->tid = tid;
    event->tgid = tgid;
    event->old_pid = old_pid;
    event->task_start_kernel_ns = start_ns;
	event->first_observed_kernel_ns = first_observed_ns;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
	event->filename[0] = 0;
	event->argc = 0;
#pragma unroll
	for (int i = 0; i < MAX_ARGS; i++) {
		event->argv[i][0] = 0;
	}

    struct argv_cache *cache = bpf_map_lookup_elem(&argv_cache_map, &pid);
    if (cache) {
        __builtin_memcpy(event->filename, cache->filename, sizeof(event->filename));
        event->argc = cache->argc;
#pragma unroll
        for (int i = 0; i < MAX_ARGS; i++) {
            __builtin_memcpy(event->argv[i], cache->argv[i], MAX_ARG_LEN);
        }
        bpf_map_delete_elem(&argv_cache_map, &pid);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int trace_sched_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 parent_tgid = pid_tgid >> 32;
    __u32 parent_tid = (__u32)ctx->parent_pid;
    __u32 child_tid = (__u32)ctx->child_pid;
    __u64 start_ns = bpf_ktime_get_ns();
    __u64 parent_start_ns = task_start(parent_tid);

    bpf_map_update_elem(&task_start_map, &child_tid, &start_ns, BPF_ANY);
    bpf_map_delete_elem(&first_observed_map, &child_tid);
    submit_process_event(PROCESS_FORK, parent_tid, parent_tgid,
                         parent_tid, parent_tgid, child_tid, 0, 0,
                         start_ns, parent_start_ns, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_exit(void *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u64 start_ns = task_start(tid);
	__u64 now = bpf_ktime_get_ns();
	__u64 first_observed_ns = start_ns ? 0 : first_observed(tid, now);

    submit_process_event(PROCESS_EXIT, tid, tgid, 0, 0, 0, 0, 0,
                         start_ns, 0, first_observed_ns);
    bpf_map_delete_elem(&task_start_map, &tid);
    bpf_map_delete_elem(&first_observed_map, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
