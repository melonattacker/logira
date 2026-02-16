// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_PATH_LEN 256

struct trace_event_raw_sys_enter {
    __u64 unused;
    long id;
    unsigned long args[6];
};

struct trace_event_raw_sys_exit {
    __u64 unused;
    long id;
    long ret;
};

struct open_how {
    __u64 flags;
    __u64 mode;
    __u64 resolve;
};

struct open_state {
    __u32 flags;
    char filename[MAX_PATH_LEN];
};

struct file_event {
    __u64 ts_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 uid;
    __u32 flags;
    __s32 fd;
    char filename[MAX_PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct open_state);
} pending_open SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline void cache_open(__u32 tid, const char *filename, __u32 flags) {
    struct open_state st = {};
    st.flags = flags;
    if (filename) {
        bpf_probe_read_user_str(st.filename, sizeof(st.filename), filename);
    }
    bpf_map_update_elem(&pending_open, &tid, &st, BPF_ANY);
}

static __always_inline void submit_open(__u32 tid, long ret) {
    struct open_state *st = bpf_map_lookup_elem(&pending_open, &tid);
    if (!st) {
        return;
    }
    if (ret < 0) {
        bpf_map_delete_elem(&pending_open, &tid);
        return;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 uid = (__u32)bpf_get_current_uid_gid();

    struct file_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        bpf_map_delete_elem(&pending_open, &tid);
        return;
    }
    ev->ts_ns = bpf_ktime_get_ns();
    ev->cgroup_id = bpf_get_current_cgroup_id();
    ev->pid = pid;
    ev->uid = uid;
    ev->flags = st->flags;
    ev->fd = (__s32)ret;
    __builtin_memcpy(ev->filename, st->filename, sizeof(ev->filename));
    bpf_ringbuf_submit(ev, 0);

    bpf_map_delete_elem(&pending_open, &tid);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    const char *filename = (const char *)ctx->args[1];
    __u32 flags = (__u32)ctx->args[2];
    cache_open(tid, filename, flags);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    submit_open(tid, ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_enter_openat2(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    const char *filename = (const char *)ctx->args[1];
    const struct open_how *howp = (const struct open_how *)ctx->args[2];

    struct open_how how = {};
    if (howp) {
        bpf_probe_read_user(&how, sizeof(how), howp);
    }
    cache_open(tid, filename, (__u32)how.flags);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int trace_exit_openat2(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    submit_open(tid, ctx->ret);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

