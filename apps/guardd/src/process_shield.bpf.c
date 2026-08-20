// LPS3 Process Shield policy. Userspace populates `targets` only for an exact
// Firefox Main SecretAuthority instance (TGID + start time). Every other
// target returns the prior LSM decision untouched.
#include <linux/bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct task_struct {
    unsigned int tgid;
    unsigned long long start_boottime;
} __attribute__((preserve_access_index));

struct target_instance {
    unsigned long long start_jiffies;
    unsigned int hz;
};

struct process_shield_audit {
    unsigned int requester_pid;
    unsigned int target_pid;
    unsigned long long target_start_jiffies;
    unsigned int operation_kind;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, unsigned int);
    __type(value, struct target_instance);
} targets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} audit SEC(".maps");

SEC("lsm/ptrace_access_check")
int BPF_PROG(guardd_process_shield_ptrace, struct task_struct *child,
             unsigned int mode, int ret)
{
    unsigned int target_pid = BPF_CORE_READ(child, tgid);
    struct target_instance *expected = bpf_map_lookup_elem(&targets, &target_pid);
    if (!expected || !expected->hz)
        return ret;

    unsigned long long start_ns = BPF_CORE_READ(child, start_boottime);
    unsigned long long start_jiffies = start_ns / (1000000000ULL / expected->hz);
    if (start_jiffies != expected->start_jiffies)
        return ret; // stale entry or PID reuse: never protect a new process.

    // The target itself and root are outside this same-user threat boundary.
    // Unknown same-UID requesters reach the denial below; no browser-tree or
    // browser-family exemption exists. Root is also the daemon's /proc
    // observer, so denying it here would make its own identity scans recurse.
    unsigned int requester_pid = (unsigned int)bpf_get_current_pid_tgid();
    if (requester_pid == target_pid || (unsigned int)bpf_get_current_uid_gid() == 0)
        return ret;

    struct process_shield_audit *event = bpf_ringbuf_reserve(&audit, sizeof(*event), 0);
    if (event) {
        event->requester_pid = requester_pid;
        event->target_pid = target_pid;
        event->target_start_jiffies = start_jiffies;
        event->operation_kind = mode;
        bpf_ringbuf_submit(event, 0);
    }
    return -1; // EPERM for an unknown same-user ptrace attempt.
}

char LICENSE[] SEC("license") = "GPL";
