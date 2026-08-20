// LPS1 synthetic ptrace guard. This is test-only policy: userspace installs
// one exact PID + start-time-jiffies target and removes it before exit.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct task_struct {
    unsigned int tgid;
    unsigned long long start_boottime;
} __attribute__((preserve_access_index));

struct target_instance {
    unsigned long long start_jiffies;
    unsigned int hz;
};

struct audit_event {
    unsigned int requester_pid;
    unsigned int target_pid;
    unsigned long long start_jiffies;
    unsigned int kind;
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
int BPF_PROG(lps1_ptrace_guard, struct task_struct *child, unsigned int mode,
             int ret)
{
    unsigned int target_pid = BPF_CORE_READ(child, tgid);
    struct target_instance *expected = bpf_map_lookup_elem(&targets, &target_pid);
    if (!expected || !expected->hz)
        return ret;

    unsigned long long start_ns = BPF_CORE_READ(child, start_boottime);
    unsigned long long start_jiffies = start_ns / (1000000000ULL / expected->hz);
    if (start_jiffies != expected->start_jiffies)
        return ret;

    struct audit_event *event = bpf_ringbuf_reserve(&audit, sizeof(*event), 0);
    if (event) {
        event->requester_pid = (unsigned int)bpf_get_current_pid_tgid();
        event->target_pid = target_pid;
        event->start_jiffies = start_jiffies;
        event->kind = mode;
        bpf_ringbuf_submit(event, 0);
    }
    return -1; // -EPERM: target is this exact live process instance.
}

char LICENSE[] SEC("license") = "GPL";
