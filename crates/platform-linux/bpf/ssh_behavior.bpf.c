// SPDX-License-Identifier: GPL-2.0
//
// This program is intentionally small: it does not inspect payload bytes.
// It blocks an actual socket send from a process tree armed by guardd after a
// protected SSH-key read. `sched_process_fork` copies the exact parent state
// to future children; existing siblings are never added.

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define GUARD_EPERM 1

struct socket;
struct msghdr;
struct sock;
struct mnt_idmap;
struct iattr;
struct in6_addr {
    __u32 in6_u[4];
} __attribute__((preserve_access_index));
struct sock_common {
    __u16 skc_family;
    __u32 skc_daddr;
    struct in6_addr skc_v6_daddr;
} __attribute__((preserve_access_index));
struct sock {
    struct sock_common __sk_common;
} __attribute__((preserve_access_index));
struct socket {
    struct sock *sk;
} __attribute__((preserve_access_index));
struct msghdr {
    void *msg_name;
    __u32 msg_namelen;
} __attribute__((preserve_access_index));
struct sockaddr_in {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr;
} __attribute__((preserve_access_index));
struct sockaddr_in6 {
    __u16 sin6_family;
    __u16 sin6_port;
    __u32 sin6_flowinfo;
    struct in6_addr sin6_addr;
} __attribute__((preserve_access_index));
struct super_block {
    __u32 s_dev;
} __attribute__((preserve_access_index));
struct inode {
    struct super_block *i_sb;
    __u64 i_ino;
} __attribute__((preserve_access_index));
struct dentry {
    struct inode *d_inode;
} __attribute__((preserve_access_index));
struct file {
    struct inode *f_inode;
} __attribute__((preserve_access_index));

struct inode_key {
    __u64 dev;
    __u64 ino;
};

enum exposure_state {
    EXPOSURE_OBSERVING = 1,
    EXPOSURE_PENDING = 2,
    EXPOSURE_ALLOWED = 3,
};

struct exposure {
    __u64 incident_id;
    __u64 observe_until_ns;
    __u32 state;
    __u32 uid;
};

struct blocked_event {
    __u64 incident_id;
    __u64 at_ns;
    __u32 tgid;
    __u32 uid;
    __u32 size;
    __u32 reserved;
};

struct task_struct {
    __s32 pid;
    __s32 tgid;
} __attribute__((preserve_access_index));

struct process_exit_event {
    __u8 common[8];
    char comm[16];
    __s32 pid;
    __s32 prio;
    __u8 group_dead;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct exposure);
} exposures SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} blocked_events SEC(".maps");

/* Kernel-owned containment marker. Userspace may renew an observing exposure
 * after a send raced with a key read, but it cannot turn this marker back into
 * observation: the send hook checks it before expiry and arm updates. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u64);
} pending_tgids SEC(".maps");

/* A temporary inode guard makes a quarantine move compare-and-act safe. The
 * daemon's own TGID is the only mutator allowed while a transaction is active.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct inode_key);
    __type(value, __u8);
} quarantine_inodes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} quarantine_controller SEC(".maps");

static __always_inline int quarantine_guard_inode(struct inode *inode)
{
    __u32 zero = 0;
    __u32 *controller;
    struct super_block *sb;
    struct inode_key key = {};

    controller = bpf_map_lookup_elem(&quarantine_controller, &zero);
    if (controller && *controller == (__u32)(bpf_get_current_pid_tgid() >> 32))
        return 0;
    if (BPF_CORE_READ_INTO(&sb, inode, i_sb) || !sb)
        return 0;
    if (BPF_CORE_READ_INTO(&key.dev, sb, s_dev) ||
        BPF_CORE_READ_INTO(&key.ino, inode, i_ino))
        return 0;
    return bpf_map_lookup_elem(&quarantine_inodes, &key) ? -GUARD_EPERM : 0;
}

static __always_inline int quarantine_guard_dentry(struct dentry *dentry)
{
    struct inode *inode;

    if (BPF_CORE_READ_INTO(&inode, dentry, d_inode) || !inode)
        return 0;
    return quarantine_guard_inode(inode);
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(guard_future_child, struct task_struct *parent_task,
             struct task_struct *child_task)
{
    __u32 parent = BPF_CORE_READ(parent_task, tgid);
    __u32 child_pid = BPF_CORE_READ(child_task, pid);
    __u32 child = BPF_CORE_READ(child_task, tgid);
    struct exposure *exposure;

    /* A thread clone has a different PID and the same TGID. The BTF-aware
     * tracepoint exposes both task_structs, so this also handles fork from a
     * secondary thread without copying state into a stale TID entry. */
    if (!parent || !child || child_pid != child)
        return 0;
    exposure = bpf_map_lookup_elem(&exposures, &parent);
    if (!exposure)
        return 0;
    bpf_map_update_elem(&exposures, &child, exposure, BPF_ANY);
    {
        __u64 *pending = bpf_map_lookup_elem(&pending_tgids, &parent);
        if (pending)
            bpf_map_update_elem(&pending_tgids, &child, pending, BPF_ANY);
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int guard_process_exit(struct process_exit_event *ctx)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    /* sched_process_exit sets group_dead only for the final thread in the
     * group. Checking pid == tgid is insufficient: a leader can exit while
     * sibling threads remain, and must not release their containment. */
    if (ctx->group_dead) {
        bpf_map_delete_elem(&exposures, &tgid);
        bpf_map_delete_elem(&pending_tgids, &tgid);
    }
    return 0;
}

static __always_inline int ipv6_is_loopback(struct in6_addr *address)
{
    return address->in6_u[0] == 0 && address->in6_u[1] == 0 &&
           address->in6_u[2] == 0 && address->in6_u[3] == bpf_htonl(1);
}

static __always_inline int ipv6_is_unspecified(struct in6_addr *address)
{
    return address->in6_u[0] == 0 && address->in6_u[1] == 0 &&
           address->in6_u[2] == 0 && address->in6_u[3] == 0;
}

static __always_inline int external_destination(struct socket *sock,
                                                 struct msghdr *msg)
{
    struct sock *sk;
    struct sockaddr_in address4 = {};
    struct sockaddr_in6 address6 = {};
    __u16 family = 0;

    if (!sock)
        return 0;
    sk = BPF_CORE_READ(sock, sk);
    if (sk && bpf_core_read(&family, sizeof(family),
                            &sk->__sk_common.skc_family) < 0)
        return 0;

    /* Connected sockets carry their destination in struct sock. This covers
     * sockets connected before the protected-key read. */
    if (family == 2) { /* AF_INET */
        __u32 destination = 0;
        if (sk && bpf_core_read(&destination, sizeof(destination),
                                &sk->__sk_common.skc_daddr) < 0)
            return 1;
        if (destination)
            return bpf_ntohl(destination) >> 24 != 127;
    } else if (family == 10) { /* AF_INET6 */
        struct in6_addr destination6 = {};
        if (!sk || bpf_core_read(&destination6, sizeof(destination6),
                                 &sk->__sk_common.skc_v6_daddr) < 0)
            return 1;
        /* An unspecified destination means an unconnected datagram socket;
         * resolve its actual sendto destination from msghdr below. */
        if (!ipv6_is_unspecified(&destination6))
            return !ipv6_is_loopback(&destination6);
    } else {
        /* AF_UNIX, AF_NETLINK, and other local-only/unknown families are not
         * suspicious network destinations in this deliberately narrow model. */
        return 0;
    }

    /* Datagram sendto supplies the destination through msghdr. If an IPv4/6
     * destination cannot be read, fail closed: it is not provably local. */
    if (!msg)
        return 1;
    void *name = BPF_CORE_READ(msg, msg_name);
    __u32 name_len = BPF_CORE_READ(msg, msg_namelen);
    if (!name || name_len < sizeof(__u16))
        return 1;
    if (bpf_probe_read_user(&family, sizeof(family), name) < 0)
        return 1;
    if (family == 2 && name_len >= sizeof(address4)) {
        if (bpf_probe_read_user(&address4, sizeof(address4), name) < 0)
            return 1;
        return bpf_ntohl(address4.sin_addr) >> 24 != 127;
    }
    if (family == 10 && name_len >= sizeof(address6)) {
        if (bpf_probe_read_user(&address6, sizeof(address6), name) < 0)
            return 1;
        return !ipv6_is_loopback(&address6.sin6_addr);
    }
    return 1;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(guard_socket_sendmsg, struct socket *sock, struct msghdr *msg,
             int size, int ret)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct exposure *exposure;
    __u64 *pending;
    __u64 now;

    if (ret)
        return ret;
    exposure = bpf_map_lookup_elem(&exposures, &tgid);
    if (!exposure)
        return 0;
    if (exposure->state == EXPOSURE_ALLOWED)
        return 0;

    if (!external_destination(sock, msg))
        return 0;

    pending = bpf_map_lookup_elem(&pending_tgids, &tgid);
    if (pending) {
        /* Pending is kernel-owned and survives any userspace renewal. */
        exposure->state = EXPOSURE_PENDING;
        return -GUARD_EPERM;
    }

    now = bpf_ktime_get_ns();
    if (exposure->state == EXPOSURE_OBSERVING && now >= exposure->observe_until_ns) {
        bpf_map_delete_elem(&exposures, &tgid);
        return 0;
    }

    if (exposure->state == EXPOSURE_OBSERVING) {
        struct blocked_event *event;

        exposure->state = EXPOSURE_PENDING;
        bpf_map_update_elem(&pending_tgids, &tgid, &exposure->incident_id, BPF_ANY);
        event = bpf_ringbuf_reserve(&blocked_events, sizeof(*event), 0);
        if (event) {
            event->incident_id = exposure->incident_id;
            event->at_ns = now;
            event->tgid = tgid;
            event->uid = (__u32)bpf_get_current_uid_gid();
            event->size = size > 0 ? (__u32)size : 0;
            event->reserved = 0;
            bpf_ringbuf_submit(event, 0);
        }
    }

    // The send hook runs before the socket operation can transmit payload.
    return -GUARD_EPERM;
}

SEC("lsm/inode_link")
int BPF_PROG(guard_quarantine_link, struct dentry *old_dentry,
             struct inode *dir, struct dentry *new_dentry, int ret)
{
    if (ret)
        return ret;
    return quarantine_guard_dentry(old_dentry);
}

SEC("lsm/inode_unlink")
int BPF_PROG(guard_quarantine_unlink, struct inode *dir,
             struct dentry *dentry, int ret)
{
    if (ret)
        return ret;
    return quarantine_guard_dentry(dentry);
}

SEC("lsm/inode_rename")
int BPF_PROG(guard_quarantine_rename, struct inode *old_dir,
             struct dentry *old_dentry, struct inode *new_dir,
             struct dentry *new_dentry, unsigned int flags, int ret)
{
    if (ret)
        return ret;
    return quarantine_guard_dentry(old_dentry);
}

SEC("lsm/inode_setattr")
int BPF_PROG(guard_quarantine_setattr, struct mnt_idmap *idmap,
             struct dentry *dentry, struct iattr *attr, int ret)
{
    if (ret)
        return ret;
    return quarantine_guard_dentry(dentry);
}

SEC("lsm/file_permission")
int BPF_PROG(guard_quarantine_file_permission, struct file *file, int mask,
             int ret)
{
    struct inode *inode;

    if (ret || !(mask & 2))
        return ret;
    if (BPF_CORE_READ_INTO(&inode, file, f_inode) || !inode)
        return 0;
    return quarantine_guard_inode(inode);
}

char LICENSE[] SEC("license") = "GPL";
