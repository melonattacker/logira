// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_PATH_LEN 256

enum file_kind {
    FILE_OPEN = 1,
    FILE_WRITE = 2,
    FILE_RENAME = 3,
    FILE_UNLINK = 4,
    FILE_TRUNCATE = 5,
    FILE_CHDIR = 6,
    FILE_CLOSE = 7,
};

enum file_syscall {
    SC_OPENAT = 1,
    SC_OPENAT2 = 2,
    SC_WRITE = 3,
    SC_PWRITE64 = 4,
    SC_WRITEV = 5,
    SC_RENAME = 6,
    SC_RENAMEAT = 7,
    SC_RENAMEAT2 = 8,
    SC_UNLINK = 9,
    SC_UNLINKAT = 10,
    SC_TRUNCATE = 11,
    SC_FTRUNCATE = 12,
    SC_CHDIR = 13,
    SC_FCHDIR = 14,
    SC_CLOSE = 15,
};

enum correlation_state {
    CORRELATION_COMPLETE = 1,
    CORRELATION_INCOMPLETE = 2,
};

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

struct pending_file_op {
    __u64 cgroup_id;
    __u64 enter_ts_ns;
    __u32 kind;
    __u32 syscall;
    __u32 tgid;
    __u32 tid;
    __u32 uid;
    __u32 flags;
    __s32 fd;
    __s32 dirfd;
    __s32 dirfd2;
    __u32 _pad1;
    char path[MAX_PATH_LEN];
    char path2[MAX_PATH_LEN];
};

struct fd_path_key {
    __u64 cgroup_id;
    __u32 tgid;
    __s32 fd;
};

struct fd_path_value {
    __s32 dirfd;
    __u32 flags;
    char path[MAX_PATH_LEN];
};

struct file_event {
    __u64 ts_ns;
    __u64 cgroup_id;
    __u64 enter_ts_ns;
    __u32 tgid;
    __u32 tid;
    __u32 uid;
    __u32 kind;
    __u32 syscall;
    __u32 flags;
    __s32 fd;
    __s32 dirfd;
    __s32 dirfd2;
    __s32 _pad1;
    __s64 ret;
    __u8 correlation;
    __u8 _pad2[7];
    char path[MAX_PATH_LEN];
    char path2[MAX_PATH_LEN];
};

struct file_stage_counters {
    __u64 enters;
    __u64 exits;
    __u64 emitted;
    __u64 ring_drops;
    __u64 missing_enters;
    __u64 failed_exits;
    __u64 pending_update_failures;
    __u64 unattributed_writes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct pending_file_op);
} pending_file_ops SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pending_file_op);
} pending_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct fd_path_key);
    __type(value, struct fd_path_value);
} fd_paths SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct file_stage_counters);
} stage_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline struct file_stage_counters *stats(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&stage_counters, &key);
}

static __always_inline struct pending_file_op *new_pending(__u32 kind, __u32 syscall) {
    __u32 key = 0;
    struct pending_file_op *st = bpf_map_lookup_elem(&pending_scratch, &key);
    if (!st) {
        return 0;
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    st->cgroup_id = bpf_get_current_cgroup_id();
    st->enter_ts_ns = bpf_ktime_get_ns();
    st->kind = kind;
    st->syscall = syscall;
    st->tgid = pid_tgid >> 32;
    st->tid = (__u32)pid_tgid;
    st->uid = (__u32)bpf_get_current_uid_gid();
    st->flags = 0;
    st->fd = -1;
    st->dirfd = -100;
    st->dirfd2 = -100;
    st->_pad1 = 0;
    st->path[0] = 0;
    st->path2[0] = 0;
    return st;
}

static __always_inline int save_pending(struct pending_file_op *st) {
    if (!st) {
        return 0;
    }
    struct file_stage_counters *counter = stats();
    if (counter) {
        __sync_fetch_and_add(&counter->enters, 1);
    }
    if (bpf_map_update_elem(&pending_file_ops, &st->tid, st, BPF_ANY) < 0) {
        if (counter) {
            __sync_fetch_and_add(&counter->pending_update_failures, 1);
        }
    }
    return 0;
}

static __always_inline void read_path(char dst[MAX_PATH_LEN], const char *src) {
    if (src) {
        bpf_probe_read_user_str(dst, MAX_PATH_LEN, src);
    } else {
        dst[0] = 0;
    }
}

static __always_inline void load_fd_path(struct pending_file_op *st, __s32 fd) {
    st->fd = fd;
    struct fd_path_key key = {.cgroup_id = st->cgroup_id, .tgid = st->tgid, .fd = fd};
    struct fd_path_value *value = bpf_map_lookup_elem(&fd_paths, &key);
    if (!value) {
        return;
    }
    st->dirfd = value->dirfd;
    st->flags = value->flags;
    __builtin_memcpy(st->path, value->path, sizeof(st->path));
}

static __always_inline void emit_missing_enter(__u32 kind, __u32 syscall, long ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct file_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    struct file_stage_counters *counter = stats();
    if (!ev) {
        if (counter) {
            __sync_fetch_and_add(&counter->ring_drops, 1);
        }
        return;
    }
    ev->ts_ns = bpf_ktime_get_ns();
    ev->cgroup_id = bpf_get_current_cgroup_id();
    ev->enter_ts_ns = 0;
    ev->tgid = pid_tgid >> 32;
    ev->tid = (__u32)pid_tgid;
    ev->uid = (__u32)bpf_get_current_uid_gid();
    ev->kind = kind;
    ev->syscall = syscall;
    ev->flags = 0;
    ev->fd = -1;
    ev->dirfd = -100;
    ev->dirfd2 = -100;
    ev->_pad1 = 0;
    ev->ret = ret;
    ev->correlation = CORRELATION_INCOMPLETE;
    __builtin_memset(ev->_pad2, 0, sizeof(ev->_pad2));
    ev->path[0] = 0;
    ev->path2[0] = 0;
    bpf_ringbuf_submit(ev, 0);
    if (counter) {
        __sync_fetch_and_add(&counter->missing_enters, 1);
        __sync_fetch_and_add(&counter->emitted, 1);
    }
}

static __always_inline int finish_pending(__u32 expected_kind, __u32 syscall, long ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    struct pending_file_op *st = bpf_map_lookup_elem(&pending_file_ops, &tid);
    struct file_stage_counters *counter = stats();
    if (counter) {
        __sync_fetch_and_add(&counter->exits, 1);
    }
    if (!st || st->kind != expected_kind || st->syscall != syscall) {
        if (st) {
            bpf_map_delete_elem(&pending_file_ops, &tid);
        }
        emit_missing_enter(expected_kind, syscall, ret);
        return 0;
    }

    int success = 0;
    if (st->kind == FILE_OPEN) {
        success = ret >= 0;
    } else if (st->kind == FILE_WRITE) {
        success = ret > 0;
    } else {
        success = ret == 0;
    }
    if (!success) {
        if (counter) {
            __sync_fetch_and_add(&counter->failed_exits, 1);
        }
        bpf_map_delete_elem(&pending_file_ops, &tid);
        return 0;
    }

    if (st->kind == FILE_CLOSE) {
        struct fd_path_key key = {.cgroup_id = st->cgroup_id, .tgid = st->tgid, .fd = st->fd};
        bpf_map_delete_elem(&fd_paths, &key);
        bpf_map_delete_elem(&pending_file_ops, &tid);
        return 0;
    }

    /* write(2) also targets pipes and sockets. Without successful-open path
     * provenance this is not evidence of a file mutation. */
    if (st->kind == FILE_WRITE && st->path[0] == 0) {
        if (counter) {
            __sync_fetch_and_add(&counter->unattributed_writes, 1);
        }
        bpf_map_delete_elem(&pending_file_ops, &tid);
        return 0;
    }

    struct file_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        if (counter) {
            __sync_fetch_and_add(&counter->ring_drops, 1);
        }
        bpf_map_delete_elem(&pending_file_ops, &tid);
        return 0;
    }
    ev->ts_ns = bpf_ktime_get_ns();
    ev->cgroup_id = st->cgroup_id;
    ev->enter_ts_ns = st->enter_ts_ns;
    ev->tgid = st->tgid;
    ev->tid = st->tid;
    ev->uid = st->uid;
    ev->kind = st->kind;
    ev->syscall = st->syscall;
    ev->flags = st->flags;
    ev->fd = st->kind == FILE_OPEN ? (__s32)ret : st->fd;
    ev->dirfd = st->dirfd;
    ev->dirfd2 = st->dirfd2;
    ev->_pad1 = 0;
    ev->ret = ret;
    ev->correlation = CORRELATION_COMPLETE;
    __builtin_memset(ev->_pad2, 0, sizeof(ev->_pad2));
    __builtin_memcpy(ev->path, st->path, sizeof(ev->path));
    __builtin_memcpy(ev->path2, st->path2, sizeof(ev->path2));

    if (st->kind == FILE_OPEN) {
        struct fd_path_key key = {.cgroup_id = st->cgroup_id, .tgid = st->tgid, .fd = (__s32)ret};
        struct fd_path_value value = {.dirfd = st->dirfd, .flags = st->flags};
        __builtin_memcpy(value.path, st->path, sizeof(value.path));
        bpf_map_update_elem(&fd_paths, &key, &value, BPF_ANY);
    }

    bpf_ringbuf_submit(ev, 0);
    if (counter) {
        __sync_fetch_and_add(&counter->emitted, 1);
    }
    bpf_map_delete_elem(&pending_file_ops, &tid);
    return 0;
}

static __always_inline int cache_open(__u32 syscall, __s32 dirfd, const char *path, __u32 flags) {
    struct pending_file_op *st = new_pending(FILE_OPEN, syscall);
    if (!st) {
        return 0;
    }
    st->dirfd = dirfd;
    st->flags = flags;
    read_path(st->path, path);
    return save_pending(st);
}

static __always_inline int cache_fd_operation(__u32 kind, __u32 syscall, __s32 fd) {
    struct pending_file_op *st = new_pending(kind, syscall);
    if (!st) {
        return 0;
    }
    load_fd_path(st, fd);
    return save_pending(st);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    return cache_open(SC_OPENAT, (__s32)ctx->args[0], (const char *)ctx->args[1], (__u32)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    return finish_pending(FILE_OPEN, SC_OPENAT, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_enter_openat2(struct trace_event_raw_sys_enter *ctx) {
    struct open_how how = {};
    if (ctx->args[2]) {
        bpf_probe_read_user(&how, sizeof(how), (const void *)ctx->args[2]);
    }
    return cache_open(SC_OPENAT2, (__s32)ctx->args[0], (const char *)ctx->args[1], (__u32)how.flags);
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int trace_exit_openat2(struct trace_event_raw_sys_exit *ctx) {
    return finish_pending(FILE_OPEN, SC_OPENAT2, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_enter_write(struct trace_event_raw_sys_enter *ctx) {
    return cache_fd_operation(FILE_WRITE, SC_WRITE, (__s32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_exit_write(struct trace_event_raw_sys_exit *ctx) {
    return finish_pending(FILE_WRITE, SC_WRITE, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_pwrite64")
int trace_enter_pwrite64(struct trace_event_raw_sys_enter *ctx) {
    return cache_fd_operation(FILE_WRITE, SC_PWRITE64, (__s32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_pwrite64")
int trace_exit_pwrite64(struct trace_event_raw_sys_exit *ctx) {
    return finish_pending(FILE_WRITE, SC_PWRITE64, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_writev")
int trace_enter_writev(struct trace_event_raw_sys_enter *ctx) {
    return cache_fd_operation(FILE_WRITE, SC_WRITEV, (__s32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_writev")
int trace_exit_writev(struct trace_event_raw_sys_exit *ctx) {
    return finish_pending(FILE_WRITE, SC_WRITEV, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_enter_rename(struct trace_event_raw_sys_enter *ctx) {
    struct pending_file_op *st = new_pending(FILE_RENAME, SC_RENAME);
    if (!st) return 0;
    read_path(st->path, (const char *)ctx->args[0]);
    read_path(st->path2, (const char *)ctx->args[1]);
    return save_pending(st);
}

SEC("tracepoint/syscalls/sys_exit_rename")
int trace_exit_rename(struct trace_event_raw_sys_exit *ctx) {
    return finish_pending(FILE_RENAME, SC_RENAME, ctx->ret);
}

static __always_inline int cache_renameat(__u32 syscall, struct trace_event_raw_sys_enter *ctx) {
    struct pending_file_op *st = new_pending(FILE_RENAME, syscall);
    if (!st) return 0;
    st->dirfd = (__s32)ctx->args[0];
    st->dirfd2 = (__s32)ctx->args[2];
    read_path(st->path, (const char *)ctx->args[1]);
    read_path(st->path2, (const char *)ctx->args[3]);
    return save_pending(st);
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_enter_renameat(struct trace_event_raw_sys_enter *ctx) { return cache_renameat(SC_RENAMEAT, ctx); }
SEC("tracepoint/syscalls/sys_exit_renameat")
int trace_exit_renameat(struct trace_event_raw_sys_exit *ctx) { return finish_pending(FILE_RENAME, SC_RENAMEAT, ctx->ret); }
SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_enter_renameat2(struct trace_event_raw_sys_enter *ctx) { return cache_renameat(SC_RENAMEAT2, ctx); }
SEC("tracepoint/syscalls/sys_exit_renameat2")
int trace_exit_renameat2(struct trace_event_raw_sys_exit *ctx) { return finish_pending(FILE_RENAME, SC_RENAMEAT2, ctx->ret); }

SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_enter_unlink(struct trace_event_raw_sys_enter *ctx) {
    struct pending_file_op *st = new_pending(FILE_UNLINK, SC_UNLINK);
    if (!st) return 0;
    read_path(st->path, (const char *)ctx->args[0]);
    return save_pending(st);
}
SEC("tracepoint/syscalls/sys_exit_unlink")
int trace_exit_unlink(struct trace_event_raw_sys_exit *ctx) { return finish_pending(FILE_UNLINK, SC_UNLINK, ctx->ret); }

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_enter_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    struct pending_file_op *st = new_pending(FILE_UNLINK, SC_UNLINKAT);
    if (!st) return 0;
    st->dirfd = (__s32)ctx->args[0];
    read_path(st->path, (const char *)ctx->args[1]);
    return save_pending(st);
}
SEC("tracepoint/syscalls/sys_exit_unlinkat")
int trace_exit_unlinkat(struct trace_event_raw_sys_exit *ctx) { return finish_pending(FILE_UNLINK, SC_UNLINKAT, ctx->ret); }

SEC("tracepoint/syscalls/sys_enter_truncate")
int trace_enter_truncate(struct trace_event_raw_sys_enter *ctx) {
    struct pending_file_op *st = new_pending(FILE_TRUNCATE, SC_TRUNCATE);
    if (!st) return 0;
    read_path(st->path, (const char *)ctx->args[0]);
    return save_pending(st);
}
SEC("tracepoint/syscalls/sys_exit_truncate")
int trace_exit_truncate(struct trace_event_raw_sys_exit *ctx) { return finish_pending(FILE_TRUNCATE, SC_TRUNCATE, ctx->ret); }

SEC("tracepoint/syscalls/sys_enter_ftruncate")
int trace_enter_ftruncate(struct trace_event_raw_sys_enter *ctx) { return cache_fd_operation(FILE_TRUNCATE, SC_FTRUNCATE, (__s32)ctx->args[0]); }
SEC("tracepoint/syscalls/sys_exit_ftruncate")
int trace_exit_ftruncate(struct trace_event_raw_sys_exit *ctx) { return finish_pending(FILE_TRUNCATE, SC_FTRUNCATE, ctx->ret); }

SEC("tracepoint/syscalls/sys_enter_chdir")
int trace_enter_chdir(struct trace_event_raw_sys_enter *ctx) {
    struct pending_file_op *st = new_pending(FILE_CHDIR, SC_CHDIR);
    if (!st) return 0;
    read_path(st->path, (const char *)ctx->args[0]);
    return save_pending(st);
}
SEC("tracepoint/syscalls/sys_exit_chdir")
int trace_exit_chdir(struct trace_event_raw_sys_exit *ctx) { return finish_pending(FILE_CHDIR, SC_CHDIR, ctx->ret); }

SEC("tracepoint/syscalls/sys_enter_fchdir")
int trace_enter_fchdir(struct trace_event_raw_sys_enter *ctx) { return cache_fd_operation(FILE_CHDIR, SC_FCHDIR, (__s32)ctx->args[0]); }
SEC("tracepoint/syscalls/sys_exit_fchdir")
int trace_exit_fchdir(struct trace_event_raw_sys_exit *ctx) { return finish_pending(FILE_CHDIR, SC_FCHDIR, ctx->ret); }

SEC("tracepoint/syscalls/sys_enter_close")
int trace_enter_close(struct trace_event_raw_sys_enter *ctx) { return cache_fd_operation(FILE_CLOSE, SC_CLOSE, (__s32)ctx->args[0]); }
SEC("tracepoint/syscalls/sys_exit_close")
int trace_exit_close(struct trace_event_raw_sys_exit *ctx) { return finish_pending(FILE_CLOSE, SC_CLOSE, ctx->ret); }

char LICENSE[] SEC("license") = "Dual BSD/GPL";
