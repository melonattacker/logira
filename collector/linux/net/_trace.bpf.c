#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define OP_CONNECT 1
#define OP_SEND 2
#define OP_RECV 3

#ifndef AF_INET
#define AF_INET 2
#endif

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

struct addr_info {
    __u32 ip4;
    __u16 port;
    __u16 family;
};

struct io_state {
    __s32 fd;
    __u8 op;
    __u8 _pad1;
    __u16 _pad2;
    struct addr_info addr;
};

struct fd_key {
    __u32 pid;
    __s32 fd;
};

struct net_event {
    __u64 ts_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 uid;
    __u8 op;
    __u8 proto;
    __u16 _pad1;
    __u32 ip4;
    __u16 port;
    __u16 _pad2;
    __s64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32);
    __type(value, struct io_state);
} pending_connect SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32);
    __type(value, struct io_state);
} pending_io SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct fd_key);
    __type(value, struct addr_info);
} fd_addr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int read_sockaddr(const void *addr, __u64 addrlen, struct addr_info *out) {
    if (!addr || !out) {
        return -1;
    }

    __u16 family = 0;
    /* sa_family is the first field in sockaddr. */
    if (bpf_probe_read_user(&family, sizeof(family), addr) < 0) {
        return -1;
    }

    out->family = family;
    if (family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in s4;
        if (bpf_probe_read_user(&s4, sizeof(s4), addr) < 0) {
            return -1;
        }
        out->ip4 = s4.sin_addr.s_addr;
        out->port = bpf_ntohs(s4.sin_port);
        return 0;
    }

    return -1;
}

static __always_inline void submit_event(__u32 pid, __u32 uid, __u8 op, struct addr_info *addr, __s64 bytes) {
    struct net_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return;
    }
    event->ts_ns = bpf_ktime_get_ns();
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->pid = pid;
    event->uid = uid;
    event->op = op;
    event->proto = 0;
    event->ip4 = 0;
    event->port = 0;
    event->bytes = bytes;

    if (addr && addr->family == AF_INET) {
        event->ip4 = addr->ip4;
        event->port = addr->port;
    }

    bpf_ringbuf_submit(event, 0);
}

static __always_inline int handle_send_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 pid = pid_tgid >> 32;
    __u32 uid = (__u32)bpf_get_current_uid_gid();

    struct io_state *state = bpf_map_lookup_elem(&pending_io, &tid);
    if (!state) {
        return 0;
    }

    if (ctx->ret > 0 && state->op == OP_SEND) {
        struct addr_info addr = state->addr;
        if (addr.family == 0) {
            struct fd_key key = {.pid = pid, .fd = state->fd};
            struct addr_info *cached = bpf_map_lookup_elem(&fd_addr, &key);
            if (cached) {
                addr = *cached;
            }
        }
        submit_event(pid, uid, OP_SEND, &addr, ctx->ret);
    }

    bpf_map_delete_elem(&pending_io, &tid);
    return 0;
}

static __always_inline int handle_recv_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 pid = pid_tgid >> 32;
    __u32 uid = (__u32)bpf_get_current_uid_gid();

    struct io_state *state = bpf_map_lookup_elem(&pending_io, &tid);
    if (!state) {
        return 0;
    }

    if (ctx->ret > 0 && state->op == OP_RECV) {
        struct addr_info addr = state->addr;
        if (addr.family == 0) {
            struct fd_key key = {.pid = pid, .fd = state->fd};
            struct addr_info *cached = bpf_map_lookup_elem(&fd_addr, &key);
            if (cached) {
                addr = *cached;
            }
        }
        submit_event(pid, uid, OP_RECV, &addr, ctx->ret);
    }

    bpf_map_delete_elem(&pending_io, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    struct io_state state;
    state.fd = (__s32)ctx->args[0];
    state.op = OP_CONNECT;
    state._pad1 = 0;
    state._pad2 = 0;
    state.addr.ip4 = 0;
    state.addr.port = 0;
    state.addr.family = 0;
    read_sockaddr((const void *)ctx->args[1], ctx->args[2], &state.addr);
    bpf_map_update_elem(&pending_connect, &tid, &state, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_exit_connect(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 pid = pid_tgid >> 32;
    __u32 uid = (__u32)bpf_get_current_uid_gid();

    struct io_state *state = bpf_map_lookup_elem(&pending_connect, &tid);
    if (!state) {
        return 0;
    }

    if (ctx->ret == 0) {
        submit_event(pid, uid, OP_CONNECT, &state->addr, 0);
        struct fd_key key = {.pid = pid, .fd = state->fd};
        bpf_map_update_elem(&fd_addr, &key, &state->addr, BPF_ANY);
    }

    bpf_map_delete_elem(&pending_connect, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    struct io_state state;
    state.fd = (__s32)ctx->args[0];
    state.op = OP_SEND;
    state._pad1 = 0;
    state._pad2 = 0;
    state.addr.ip4 = 0;
    state.addr.port = 0;
    state.addr.family = 0;
    read_sockaddr((const void *)ctx->args[4], ctx->args[5], &state.addr);
    bpf_map_update_elem(&pending_io, &tid, &state, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_enter_sendmsg(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    struct io_state state;
    state.fd = (__s32)ctx->args[0];
    state.op = OP_SEND;
    state._pad1 = 0;
    state._pad2 = 0;
    state.addr.ip4 = 0;
    state.addr.port = 0;
    state.addr.family = 0;
    bpf_map_update_elem(&pending_io, &tid, &state, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_enter_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    struct io_state state;
    state.fd = (__s32)ctx->args[0];
    state.op = OP_RECV;
    state._pad1 = 0;
    state._pad2 = 0;
    state.addr.ip4 = 0;
    state.addr.port = 0;
    state.addr.family = 0;
    bpf_map_update_elem(&pending_io, &tid, &state, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int trace_enter_recvmsg(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    struct io_state state;
    state.fd = (__s32)ctx->args[0];
    state.op = OP_RECV;
    state._pad1 = 0;
    state._pad2 = 0;
    state.addr.ip4 = 0;
    state.addr.port = 0;
    state.addr.family = 0;
    bpf_map_update_elem(&pending_io, &tid, &state, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int trace_exit_sendto(struct trace_event_raw_sys_exit *ctx) {
    return handle_send_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_sendmsg")
int trace_exit_sendmsg(struct trace_event_raw_sys_exit *ctx) {
    return handle_send_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_exit_recvfrom(struct trace_event_raw_sys_exit *ctx) {
    return handle_recv_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int trace_exit_recvmsg(struct trace_event_raw_sys_exit *ctx) {
    return handle_recv_exit(ctx);
}

char LICENSE[] SEC("license") = "GPL";
