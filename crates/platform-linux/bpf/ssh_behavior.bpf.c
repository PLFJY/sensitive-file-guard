// SPDX-License-Identifier: GPL-2.0
//
// This program is intentionally small: it does not inspect payload bytes.
// It blocks an actual socket send from a process tree armed by guardd after a
// protected SSH-key read. `sched_process_fork` copies the exact parent state
// to future children; existing siblings are never added.

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define GUARD_EPERM 1

struct socket;
struct msghdr;
struct mnt_idmap;
struct iattr;
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

struct fork_event {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    char parent_comm[16];
    __s32 parent_pid;
    char child_comm[16];
    __s32 child_pid;
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

SEC("tracepoint/sched/sched_process_fork")
int guard_future_child(struct fork_event *ctx)
{
    __u32 parent = (__u32)ctx->parent_pid;
    __u32 child = (__u32)ctx->child_pid;
    struct exposure *exposure;

    if (!parent || !child)
        return 0;
    exposure = bpf_map_lookup_elem(&exposures, &parent);
    if (!exposure)
        return 0;
    bpf_map_update_elem(&exposures, &child, exposure, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int guard_process_exit(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;

    if (pid == tgid)
        bpf_map_delete_elem(&exposures, &tgid);
    return 0;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(guard_socket_sendmsg, struct socket *sock, struct msghdr *msg,
             int size, int ret)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct exposure *exposure;
    __u64 now;

    if (ret)
        return ret;
    exposure = bpf_map_lookup_elem(&exposures, &tgid);
    if (!exposure)
        return 0;
    if (exposure->state == EXPOSURE_ALLOWED)
        return 0;

    now = bpf_ktime_get_ns();
    if (exposure->state == EXPOSURE_OBSERVING && now >= exposure->observe_until_ns) {
        bpf_map_delete_elem(&exposures, &tgid);
        return 0;
    }

    if (exposure->state == EXPOSURE_OBSERVING) {
        struct blocked_event *event;

        exposure->state = EXPOSURE_PENDING;
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
