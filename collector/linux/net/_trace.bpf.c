// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define NET_ABI_VERSION 1
#define OP_CONNECT 1
#define OP_SEND 2
#define OP_RECV 3
#define CONNECT_COMPLETED 1
#define CONNECT_IN_PROGRESS 2
#define PROTO_TCP 6
#define PROTO_UDP 17
#define SOCKET_TYPE_MASK 0xf
#define SOCKET_STREAM 1
#define SOCKET_DGRAM 2

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
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

/* sockaddr-derived fields remain byte arrays in network order. */
struct addr_info {
    __u8 family;
    __u8 address[16];
    __u8 port_be[2];
};

struct io_state {
    __s32 fd;
    __u8 op;
    __u8 proto;
    __u8 _pad[2];
    struct addr_info addr;
};

struct fd_key {
    __u32 tgid;
    __s32 fd;
};

/*
 * Architecture-independent wire ABI.
 *
 * sockaddr port/address bytes are copied unchanged. Host-order scalar values
 * are converted to big-endian before submission. Signed bytes uses the
 * two's-complement uint64 representation.
 */
struct net_event_wire {
    __u8 abi_version;
    __u8 event_kind;
    __u8 family;
    __u8 proto;
    __u8 connect_state;
    __u8 reserved0[3];
    __u8 address[16];
    __u8 port_be[2];
    __u8 reserved1[6];
    __u64 timestamp_be;
    __u64 cgroup_id_be;
    __u32 pid_be;
    __u32 tid_be;
    __u32 tgid_be;
    __u32 uid_be;
    __u64 bytes_be;
};

_Static_assert(sizeof(struct net_event_wire) == 72, "net_event_wire size");
_Static_assert(__builtin_offsetof(struct net_event_wire, abi_version) == 0, "abi_version offset");
_Static_assert(__builtin_offsetof(struct net_event_wire, event_kind) == 1, "event_kind offset");
_Static_assert(__builtin_offsetof(struct net_event_wire, family) == 2, "family offset");
_Static_assert(__builtin_offsetof(struct net_event_wire, proto) == 3, "proto offset");
_Static_assert(__builtin_offsetof(struct net_event_wire, connect_state) == 4, "connect_state offset");
_Static_assert(__builtin_offsetof(struct net_event_wire, address) == 8, "address offset");
_Static_assert(__builtin_offsetof(struct net_event_wire, port_be) == 24, "port offset");
_Static_assert(__builtin_offsetof(struct net_event_wire, timestamp_be) == 32, "timestamp offset");
_Static_assert(__builtin_offsetof(struct net_event_wire, cgroup_id_be) == 40, "cgroup offset");
_Static_assert(__builtin_offsetof(struct net_event_wire, pid_be) == 48, "pid offset");
_Static_assert(__builtin_offsetof(struct net_event_wire, tid_be) == 52, "tid offset");
_Static_assert(__builtin_offsetof(struct net_event_wire, tgid_be) == 56, "tgid offset");
_Static_assert(__builtin_offsetof(struct net_event_wire, uid_be) == 60, "uid offset");
_Static_assert(__builtin_offsetof(struct net_event_wire, bytes_be) == 64, "bytes offset");

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

/* Minimal socket lifecycle metadata; this is not general FD provenance. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32);
    __type(value, __u8);
} pending_socket SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct fd_key);
    __type(value, __u8);
} fd_proto SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32);
    __type(value, __s32);
} pending_close SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline void clear_addr(struct addr_info *out) {
    out->family = 0;
    __builtin_memset(out->address, 0, sizeof(out->address));
    __builtin_memset(out->port_be, 0, sizeof(out->port_be));
}

static __always_inline int read_sockaddr(const void *addr, __u64 addrlen, struct addr_info *out) {
    if (!addr || !out) {
        return -1;
    }

    __u16 family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), addr) < 0) {
        return -1;
    }

    if (family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in s4 = {};
        if (bpf_probe_read_user(&s4, sizeof(s4), addr) < 0) {
            return -1;
        }
        out->family = AF_INET;
        /* No byte swap: these are already network-order sockaddr bytes. */
        __builtin_memcpy(out->address, &s4.sin_addr.s_addr, 4);
        __builtin_memcpy(out->port_be, &s4.sin_port, 2);
        return 0;
    }

    if (family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 s6 = {};
        if (bpf_probe_read_user(&s6, sizeof(s6), addr) < 0) {
            return -1;
        }
        out->family = AF_INET6;
        __builtin_memcpy(out->address, &s6.sin6_addr, 16);
        __builtin_memcpy(out->port_be, &s6.sin6_port, 2);
        return 0;
    }

    return -1;
}

static __always_inline __u8 proto_for_fd(__u32 tgid, __s32 fd) {
    struct fd_key key = {.tgid = tgid, .fd = fd};
    __u8 *proto = bpf_map_lookup_elem(&fd_proto, &key);
    return proto ? *proto : 0;
}

static __always_inline void submit_event(__u8 op, __u8 connect_state, __u8 proto,
                                         struct addr_info *addr, __s64 bytes) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u32 uid = (__u32)bpf_get_current_uid_gid();
    struct net_event_wire *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return;
    }

    event->abi_version = NET_ABI_VERSION;
    event->event_kind = op;
    event->family = addr ? addr->family : 0;
    event->proto = proto;
    event->connect_state = connect_state;
    __builtin_memset(event->reserved0, 0, sizeof(event->reserved0));
    __builtin_memset(event->address, 0, sizeof(event->address));
    __builtin_memset(event->port_be, 0, sizeof(event->port_be));
    __builtin_memset(event->reserved1, 0, sizeof(event->reserved1));
    if (addr) {
        __builtin_memcpy(event->address, addr->address, sizeof(event->address));
        /* Direct copy: applying bpf_htons here would swap the port twice. */
        __builtin_memcpy(event->port_be, addr->port_be, sizeof(event->port_be));
    }

    event->timestamp_be = bpf_cpu_to_be64(bpf_ktime_get_ns());
    event->cgroup_id_be = bpf_cpu_to_be64(bpf_get_current_cgroup_id());
    event->pid_be = bpf_htonl(tgid);
    event->tid_be = bpf_htonl(tid);
    event->tgid_be = bpf_htonl(tgid);
    event->uid_be = bpf_htonl(uid);
    event->bytes_be = bpf_cpu_to_be64((__u64)bytes);

    bpf_ringbuf_submit(event, 0);
}

static __always_inline int handle_io_exit(struct trace_event_raw_sys_exit *ctx, __u8 expected_op) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
    struct io_state *state = bpf_map_lookup_elem(&pending_io, &tid);
    if (!state) {
        return 0;
    }

    if (ctx->ret > 0 && state->op == expected_op) {
        struct addr_info addr = state->addr;
        if (addr.family == 0) {
            struct fd_key key = {.tgid = tgid, .fd = state->fd};
            struct addr_info *cached = bpf_map_lookup_elem(&fd_addr, &key);
            if (cached) {
                addr = *cached;
            }
        }
        submit_event(expected_op, 0, state->proto, &addr, ctx->ret);
    }

    bpf_map_delete_elem(&pending_io, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int trace_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __s32 socket_type = (__s32)ctx->args[1] & SOCKET_TYPE_MASK;
    __u8 proto = 0;
    if (socket_type == SOCKET_STREAM) {
        proto = PROTO_TCP;
    } else if (socket_type == SOCKET_DGRAM) {
        proto = PROTO_UDP;
    }
    bpf_map_update_elem(&pending_socket, &tid, &proto, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_socket")
int trace_exit_socket(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
    __u8 *proto = bpf_map_lookup_elem(&pending_socket, &tid);
    if (proto && ctx->ret >= 0) {
        struct fd_key key = {.tgid = tgid, .fd = (__s32)ctx->ret};
        bpf_map_update_elem(&fd_proto, &key, proto, BPF_ANY);
    }
    bpf_map_delete_elem(&pending_socket, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_enter_close(struct trace_event_raw_sys_enter *ctx) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __s32 fd = (__s32)ctx->args[0];
    bpf_map_update_elem(&pending_close, &tid, &fd, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int trace_exit_close(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
    __s32 *fd = bpf_map_lookup_elem(&pending_close, &tid);
    if (fd && ctx->ret == 0) {
        struct fd_key key = {.tgid = tgid, .fd = *fd};
        bpf_map_delete_elem(&fd_addr, &key);
        bpf_map_delete_elem(&fd_proto, &key);
    }
    bpf_map_delete_elem(&pending_close, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
    struct io_state state = {.fd = (__s32)ctx->args[0], .op = OP_CONNECT};
    state.proto = proto_for_fd(tgid, state.fd);
    clear_addr(&state.addr);
    read_sockaddr((const void *)ctx->args[1], ctx->args[2], &state.addr);
    bpf_map_update_elem(&pending_connect, &tid, &state, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_exit_connect(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
    struct io_state *state = bpf_map_lookup_elem(&pending_connect, &tid);
    if (!state) {
        return 0;
    }

    __u8 connect_state = 0;
    if (ctx->ret == 0) {
        connect_state = CONNECT_COMPLETED;
    } else if (ctx->ret == -EINPROGRESS) {
        connect_state = CONNECT_IN_PROGRESS;
    }
    if (connect_state != 0) {
        submit_event(OP_CONNECT, connect_state, state->proto, &state->addr, 0);
        /* Both completed and EINPROGRESS sockets retain their target. */
        struct fd_key key = {.tgid = tgid, .fd = state->fd};
        bpf_map_update_elem(&fd_addr, &key, &state->addr, BPF_ANY);
    }

    bpf_map_delete_elem(&pending_connect, &tid);
    return 0;
}

static __always_inline int cache_io(__u8 op, __s32 fd, const void *addr, __u64 addrlen) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
    struct io_state state = {.fd = fd, .op = op};
    state.proto = proto_for_fd(tgid, fd);
    clear_addr(&state.addr);
    if (addr) {
        read_sockaddr(addr, addrlen, &state.addr);
    }
    bpf_map_update_elem(&pending_io, &tid, &state, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    return cache_io(OP_SEND, (__s32)ctx->args[0], (const void *)ctx->args[4], ctx->args[5]);
}
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_enter_sendmsg(struct trace_event_raw_sys_enter *ctx) {
    return cache_io(OP_SEND, (__s32)ctx->args[0], 0, 0);
}
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_enter_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    return cache_io(OP_RECV, (__s32)ctx->args[0], 0, 0);
}
SEC("tracepoint/syscalls/sys_enter_recvmsg")
int trace_enter_recvmsg(struct trace_event_raw_sys_enter *ctx) {
    return cache_io(OP_RECV, (__s32)ctx->args[0], 0, 0);
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int trace_exit_sendto(struct trace_event_raw_sys_exit *ctx) { return handle_io_exit(ctx, OP_SEND); }
SEC("tracepoint/syscalls/sys_exit_sendmsg")
int trace_exit_sendmsg(struct trace_event_raw_sys_exit *ctx) { return handle_io_exit(ctx, OP_SEND); }
SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_exit_recvfrom(struct trace_event_raw_sys_exit *ctx) { return handle_io_exit(ctx, OP_RECV); }
SEC("tracepoint/syscalls/sys_exit_recvmsg")
int trace_exit_recvmsg(struct trace_event_raw_sys_exit *ctx) { return handle_io_exit(ctx, OP_RECV); }

char LICENSE[] SEC("license") = "Dual BSD/GPL";
