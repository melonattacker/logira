/* SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 * Conservative descriptor-cache generations. A forked task starts with unknown
 * inherited descriptors. Exec/close_range invalidate cached provenance rather
 * than guessing which descriptors survived. LRU eviction causes missing data,
 * never a return to an earlier generation.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} fd_epochs SEC(".maps");

static __always_inline __u64 fd_epoch(__u32 tgid) {
    __u64 *epoch = bpf_map_lookup_elem(&fd_epochs, &tgid);
    if (epoch) return *epoch;
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&fd_epochs, &tgid, &now, BPF_NOEXIST);
    epoch = bpf_map_lookup_elem(&fd_epochs, &tgid);
    return epoch ? *epoch : now;
}

static __always_inline void invalidate_fd_epoch(__u32 pid) {
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&fd_epochs, &pid, &now, BPF_ANY);
}

struct fd_epoch_fork_ctx {
    __u64 unused;
    char parent_comm[16];
    __s32 parent_pid;
    char child_comm[16];
    __s32 child_pid;
};

SEC("tracepoint/sched/sched_process_fork")
int trace_fd_fork(struct fd_epoch_fork_ctx *ctx) {
    invalidate_fd_epoch((__u32)ctx->child_pid);
    return 0;
}
SEC("tracepoint/sched/sched_process_exec")
int trace_fd_exec(void *ctx) {
    invalidate_fd_epoch(bpf_get_current_pid_tgid() >> 32);
    return 0;
}
SEC("tracepoint/syscalls/sys_enter_close_range")
int trace_fd_close_range(void *ctx) {
    invalidate_fd_epoch(bpf_get_current_pid_tgid() >> 32);
    return 0;
}
