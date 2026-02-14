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
    char comm[16];
    char filename[MAX_ARG_LEN];
    __u32 argc;
    char argv[MAX_ARGS][MAX_ARG_LEN];
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
int trace_sched_exec(void *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 uid = (__u32)bpf_get_current_uid_gid();

    struct exec_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&argv_cache_map, &pid);
        return 0;
    }

    event->ts_ns = bpf_ktime_get_ns();
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->pid = pid;
    event->ppid = 0;
    event->uid = uid;
    bpf_get_current_comm(event->comm, sizeof(event->comm));

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

char LICENSE[] SEC("license") = "GPL";
