// LPS1/LPS5 same-non-root-UID synthetic process-control oracle. The short-lived
// root supervisor loads the BPF LSM program; the attacker is the target's
// same-UID parent, which makes the Guard-OFF ptrace baseline legal under Yama.
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct target_instance { uint64_t start_jiffies; uint32_t hz; };
struct audit_event { uint32_t requester_pid, target_pid; uint64_t start_jiffies; uint32_t kind; };
struct audit_state { uint32_t requester_pid, target_pid; uint64_t start_jiffies; uint32_t kind; bool seen; };

static void stop_and_reap(pid_t pid);

static int on_audit(void *ctx, void *data, size_t size) {
    if (size != sizeof(struct audit_event)) return 0;
    struct audit_state *out = ctx;
    memcpy(out, data, sizeof(*out)); out->seen = true;
    return 0;
}

static uint64_t proc_start_jiffies(pid_t pid) {
    char path[64], text[4096], *field;
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *file = fopen(path, "r");
    if (!file || !fgets(text, sizeof(text), file)) { if (file) fclose(file); return 0; }
    fclose(file);
    field = strrchr(text, ')');
    if (!field) return 0;
    field++;
    // Fields after ')' start at proc field 3; starttime is field 22.
    for (int n = 3; n <= 22; n++) {
        while (*field == ' ') field++;
        char *next = strchr(field, ' ');
        if (!next) return 0;
        if (n == 22) return strtoull(field, NULL, 10);
        field = next;
    }
    return 0;
}

static int read_ready(const char *path, pid_t *pid, uint8_t canary[64], uintptr_t *address) {
    FILE *file = fopen(path, "r"); char hex[129], pointer[64];
    if (!file || fscanf(file, "%d %128s %63s", pid, hex, pointer) != 3) { if (file) fclose(file); return -1; }
    fclose(file);
    if (strlen(hex) != 128) return -1;
    for (size_t i = 0; i < 64; i++) if (sscanf(hex + i * 2, "%2hhx", &canary[i]) != 1) return -1;
    *address = (uintptr_t)strtoull(pointer, NULL, 0);
    return 0;
}

static int ptrace_read(pid_t target, uintptr_t address, const uint8_t expected[64]) {
    if (ptrace(PTRACE_SEIZE, target, NULL, NULL) < 0) return -1;
    if (ptrace(PTRACE_INTERRUPT, target, NULL, NULL) < 0 || waitpid(target, NULL, 0) < 0) return -1;
    uint8_t recovered[64]; errno = 0;
    for (size_t offset = 0; offset < sizeof(recovered); offset += sizeof(long)) {
        long word = ptrace(PTRACE_PEEKDATA, target, (void *)(address + offset), NULL);
        if (word == -1 && errno) { ptrace(PTRACE_DETACH, target, NULL, NULL); return -1; }
        memcpy(recovered + offset, &word, sizeof(word));
    }
    ptrace(PTRACE_DETACH, target, NULL, NULL);
    return memcmp(recovered, expected, sizeof(recovered)) == 0 ? 1 : 0;
}

static int process_vm_read_canary(pid_t target, uintptr_t address, const uint8_t expected[64]) {
    uint8_t recovered[64];
    struct iovec local = { .iov_base = recovered, .iov_len = sizeof(recovered) };
    struct iovec remote = { .iov_base = (void *)address, .iov_len = sizeof(recovered) };
    ssize_t bytes = process_vm_readv(target, &local, 1, &remote, 1, 0);
    return bytes == (ssize_t)sizeof(recovered) ? memcmp(recovered, expected, sizeof(recovered)) == 0 : -1;
}

static int process_vm_write_synthetic(pid_t target, uintptr_t address) {
    uint8_t replacement = 0xa5;
    struct iovec local = { .iov_base = &replacement, .iov_len = sizeof(replacement) };
    struct iovec remote = { .iov_base = (void *)address, .iov_len = sizeof(replacement) };
    return process_vm_writev(target, &local, 1, &remote, 1, 0) == (ssize_t)sizeof(replacement) ? 1 : -1;
}

static int proc_mem_read_canary(pid_t target, uintptr_t address, const uint8_t expected[64]) {
    char path[64]; uint8_t recovered[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", target);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t bytes = pread(fd, recovered, sizeof(recovered), (off_t)address);
    close(fd);
    return bytes == (ssize_t)sizeof(recovered) ? memcmp(recovered, expected, sizeof(recovered)) == 0 : -1;
}

static int ptrace_attach_only(pid_t target) {
    if (ptrace(PTRACE_SEIZE, target, NULL, NULL) < 0) return -1;
    if (ptrace(PTRACE_INTERRUPT, target, NULL, NULL) < 0 || waitpid(target, NULL, 0) < 0) return -1;
    return ptrace(PTRACE_DETACH, target, NULL, NULL) == 0 ? 1 : -1;
}

static int perform_operation(const char *operation, pid_t target, uintptr_t address, const uint8_t expected[64]) {
    if (!strcmp(operation, "ptrace")) return ptrace_read(target, address, expected);
    if (!strcmp(operation, "process_vm_readv")) return process_vm_read_canary(target, address, expected);
    if (!strcmp(operation, "process_vm_writev")) return process_vm_write_synthetic(target, address);
    if (!strcmp(operation, "proc_mem")) return proc_mem_read_canary(target, address, expected);
    return -2;
}

static int unrelated_ptrace_remains_allowed(void) {
    pid_t unrelated = fork();
    if (unrelated < 0) return -1;
    if (unrelated == 0) { execl("/bin/sleep", "sleep", "20", NULL); _exit(127); }
    // The attacker is this process's same-UID parent, so Yama permits the
    // baseline. The BPF map deliberately contains a different target TGID.
    usleep(100000);
    int outcome = ptrace_attach_only(unrelated);
    stop_and_reap(unrelated);
    return outcome;
}

static int unrelated_ptrace_benchmark(void) {
    pid_t unrelated = fork();
    if (unrelated < 0) return -1;
    if (unrelated == 0) { execl("/bin/sleep", "sleep", "20", NULL); _exit(127); }
    usleep(100000);
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int outcome = 1;
    for (int attempt = 0; attempt < 100; attempt++) {
        if (ptrace_attach_only(unrelated) != 1) { outcome = -1; break; }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    stop_and_reap(unrelated);
    unsigned long long elapsed_ns = (unsigned long long)(end.tv_sec - start.tv_sec) * 1000000000ULL +
        (unsigned long long)(end.tv_nsec - start.tv_nsec);
    dprintf(STDOUT_FILENO, "LPS6_UNRELATED_PTRACE_BENCH_100_NS=%llu\n", elapsed_ns);
    return outcome;
}

static const char *operation_label(const char *operation) {
    if (!strcmp(operation, "ptrace")) return "PTRACE";
    if (!strcmp(operation, "process_vm_readv")) return "PROCESS_VM_READV";
    if (!strcmp(operation, "process_vm_writev")) return "PROCESS_VM_WRITEV";
    if (!strcmp(operation, "proc_mem")) return "PROC_MEM";
    if (!strcmp(operation, "unrelated_ptrace")) return "UNRELATED_PTRACE";
    if (!strcmp(operation, "unrelated_ptrace_benchmark")) return "UNRELATED_PTRACE_BENCHMARK";
    return NULL;
}

static int parse_id(const char *name, const char *text, unsigned long *out) {
    char *end = NULL; errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno || !text[0] || !end || *end || value > UINT32_MAX) {
        fprintf(stderr, "invalid %s: %s\n", name, text); return -1;
    }
    *out = value; return 0;
}

static int test_identity(uid_t *uid, gid_t *gid) {
    const char *uid_text = getenv("TEST_UID");
    const char *gid_text = getenv("TEST_GID");
    if (!uid_text || !uid_text[0]) uid_text = getenv("PKEXEC_UID");
    if (!uid_text || !uid_text[0]) { fprintf(stderr, "TEST_UID or PKEXEC_UID is required\n"); return -1; }
    unsigned long numeric_uid;
    if (parse_id("TEST_UID", uid_text, &numeric_uid)) return -1;
    struct passwd *entry = getpwuid((uid_t)numeric_uid);
    if (!entry || entry->pw_uid == 0) { fprintf(stderr, "TEST_UID must name a non-root local user\n"); return -1; }
    unsigned long numeric_gid = entry->pw_gid;
    if (gid_text && gid_text[0] && parse_id("TEST_GID", gid_text, &numeric_gid)) return -1;
    *uid = (uid_t)numeric_uid; *gid = (gid_t)numeric_gid;
    return 0;
}

static void stop_and_reap(pid_t pid) {
    if (pid > 0) kill(pid, SIGTERM);
    if (pid > 0) waitpid(pid, NULL, 0);
}

int main(int argc, char **argv) {
    if (argc != 5 || (strcmp(argv[1], "off") && strcmp(argv[1], "on"))) {
        fprintf(stderr, "usage: %s off|on TARGET READY_FILE BPF_OBJECT\n", argv[0]); return 2;
    }
    if (geteuid() != 0) { fprintf(stderr, "LPS1 requires root only to load its temporary BPF LSM program\n"); return 2; }
    bool enabled = !strcmp(argv[1], "on");
    bool force_stale_target = getenv("LPS_FORCE_STALE_TARGET") != NULL;
    const char *operation = getenv("LPS_OPERATION");
    if (!operation || !operation[0]) operation = "ptrace";
    const char *label = operation_label(operation);
    if (!label) { fprintf(stderr, "unsupported LPS_OPERATION: %s\n", operation); return 2; }
    uid_t uid; gid_t gid;
    if (test_identity(&uid, &gid)) return 2;

    int ready_pipe[2], release_pipe[2];
    if (pipe(ready_pipe) || pipe(release_pipe)) { perror("pipe"); return 1; }
    // Remove exactly the caller-provided readiness file so the non-root target
    // can create it; it contains only this disposable test's random canary.
    unlink(argv[3]);
    pid_t attacker = fork();
    if (attacker < 0) { perror("fork"); return 1; }
    if (attacker == 0) {
        close(ready_pipe[0]); close(release_pipe[1]);
        if (setgroups(0, NULL) || setgid(gid) || setuid(uid)) _exit(126);
        pid_t target = fork();
        if (target == 0) { execl(argv[2], argv[2], "shield-target", argv[3], "20", NULL); _exit(127); }
        if (target < 0 || write(ready_pipe[1], &target, sizeof(target)) != sizeof(target)) _exit(125);
        close(ready_pipe[1]);
        char release;
        if (read(release_pipe[0], &release, 1) != 1) { stop_and_reap(target); _exit(124); }
        close(release_pipe[0]);
        pid_t ready_target = 0; uint8_t canary[64]; uintptr_t address = 0;
        for (int retry = 0; retry < 100 && read_ready(argv[3], &ready_target, canary, &address); retry++) usleep(10000);
        int outcome = ready_target == target && address ?
            (!strcmp(operation, "unrelated_ptrace") ? unrelated_ptrace_remains_allowed() :
             !strcmp(operation, "unrelated_ptrace_benchmark") ? unrelated_ptrace_benchmark() :
             perform_operation(operation, target, address, canary)) : -2;
        stop_and_reap(target);
        _exit(outcome == 1 ? 0 : outcome < 0 ? 3 : 4);
    }
    close(ready_pipe[1]); close(release_pipe[0]);
    pid_t target = 0;
    if (read(ready_pipe[0], &target, sizeof(target)) != sizeof(target) || target <= 0) {
        fprintf(stderr, "attacker did not create target\n"); close(release_pipe[1]); stop_and_reap(attacker); return 1;
    }
    close(ready_pipe[0]);
    uint8_t ignored_canary[64]; uintptr_t address = 0; pid_t ready_target = 0;
    for (int retry = 0; retry < 100 && read_ready(argv[3], &ready_target, ignored_canary, &address); retry++) usleep(10000);
    if (ready_target != target || !address) {
        fprintf(stderr, "target readiness failed\n"); close(release_pipe[1]); stop_and_reap(attacker); unlink(argv[3]); return 1;
    }

    struct bpf_object *object = NULL; struct bpf_link *link = NULL; struct ring_buffer *ring = NULL;
    struct audit_state audit = {0}; int result = 1;
    if (enabled) {
        object = bpf_object__open_file(argv[4], NULL);
        if (libbpf_get_error(object) || bpf_object__load(object)) { fprintf(stderr, "BPF load failed\n"); goto done; }
        struct bpf_map *map = bpf_object__find_map_by_name(object, "targets");
        struct target_instance value = { proc_start_jiffies(target), (uint32_t)sysconf(_SC_CLK_TCK) };
        if (force_stale_target) value.start_jiffies++;
        uint32_t key = target;
        if (!map || !value.start_jiffies || bpf_map_update_elem(bpf_map__fd(map), &key, &value, BPF_ANY)) {
            fprintf(stderr, "target map update failed: %s (fd=%d type=%d start=%llu hz=%u)\n",
                    strerror(errno), map ? bpf_map__fd(map) : -1, map ? bpf_map__type(map) : -1,
                    (unsigned long long)value.start_jiffies, value.hz); goto done;
        }
        const char *program_name = getenv("LPS_BPF_PROGRAM");
        if (!program_name || !program_name[0]) program_name = "lps1_ptrace_guard";
        struct bpf_program *program = bpf_object__find_program_by_name(object, program_name);
        if (!program) { fprintf(stderr, "BPF program %s missing\n", program_name); goto done; }
        link = bpf_program__attach_lsm(program);
        if (libbpf_get_error(link)) { fprintf(stderr, "BPF attach failed\n"); goto done; }
        struct bpf_map *events = bpf_object__find_map_by_name(object, "audit");
        ring = ring_buffer__new(bpf_map__fd(events), on_audit, &audit, NULL);
        if (libbpf_get_error(ring)) { fprintf(stderr, "ring setup failed\n"); goto done; }
    }
    if (write(release_pipe[1], "R", 1) != 1) { perror("release attacker"); goto done; }
    close(release_pipe[1]); release_pipe[1] = -1;
    int status = 0;
    if (waitpid(attacker, &status, 0) < 0) { perror("wait attacker"); goto done; }
    if (ring) ring_buffer__poll(ring, 250);
    if (enabled && force_stale_target && WIFEXITED(status) && WEXITSTATUS(status) == 0 && !audit.seen) {
        puts("LPS6_STALE_INSTANCE_ENTRY_DOES_NOT_BIND_NEW_TARGET=PASS"); result = 0;
    } else if (enabled && !strcmp(operation, "unrelated_ptrace_benchmark") && WIFEXITED(status) && WEXITSTATUS(status) == 0 && !audit.seen) {
        puts("LPS6_UNRELATED_PTRACE_BENCHMARK_ON=PASS"); result = 0;
    } else if (!enabled && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        if (!strcmp(operation, "ptrace"))
            puts("LPS1_OFF_SAME_UID_PTRACE_CANARY_RECOVERED=PASS");
        else if (!strcmp(operation, "unrelated_ptrace"))
            puts("LPS5_UNRELATED_NORMAL_PROCESS_OFF_UNCHANGED=PASS");
        else if (!strcmp(operation, "unrelated_ptrace_benchmark"))
            puts("LPS6_UNRELATED_PTRACE_BENCHMARK_OFF=PASS");
        else if (!strcmp(operation, "process_vm_writev"))
            puts("LPS5_PROCESS_VM_WRITEV_OFF_SYNTHETIC_WRITE_SUCCEEDED=PASS");
        else
            printf("LPS5_%s_OFF_CANARY_RECOVERED=PASS\n", label);
        result = 0;
    } else if (enabled && !strcmp(operation, "unrelated_ptrace") && WIFEXITED(status) && WEXITSTATUS(status) == 0 && !audit.seen) {
        puts("LPS5_UNRELATED_NORMAL_PROCESS_ON_UNCHANGED=PASS"); result = 0;
    } else if (enabled && WIFEXITED(status) && WEXITSTATUS(status) == 3 && audit.seen &&
               audit.requester_pid == (uint32_t)attacker && audit.target_pid == (uint32_t)target && audit.kind != 0) {
        if (!strcmp(operation, "ptrace"))
            puts("LPS1_ON_SAME_UID_PTRACE_DENIED_AUDITED_CANARY_RECOVERY=0 PASS");
        else
            printf("LPS5_%s_ON_DENIED_AUDITED_CANARY_RECOVERY=0 PASS\n", label);
        result = 0;
    } else {
        fprintf(stderr, "LPS1 oracle mismatch enabled=%d attacker_status=%d audit=%d requester=%u target=%u\n",
                enabled, status, audit.seen, audit.requester_pid, audit.target_pid);
    }
done:
    if (release_pipe[1] >= 0) { close(release_pipe[1]); stop_and_reap(attacker); }
    ring_buffer__free(ring); bpf_link__destroy(link); bpf_object__close(object); unlink(argv[3]);
    return result;
}
