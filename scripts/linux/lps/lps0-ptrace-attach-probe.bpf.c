// LPS0 capability-only BPF LSM probe. It preserves the preceding LSM result
// and is detached immediately by the companion loader; it cannot enforce.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct task_struct;

SEC("lsm/ptrace_access_check")
int BPF_PROG(lps0_ptrace_attach_probe, struct task_struct *child,
             unsigned int mode, int ret)
{
    return ret;
}

char LICENSE[] SEC("license") = "GPL";
