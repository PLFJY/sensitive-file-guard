// LPS1 same-non-root-UID synthetic process-control oracle. The short-lived
// root supervisor loads the BPF LSM program; the attacker is the target's
// same-UID parent, which makes the Guard-OFF ptrace baseline legal under Yama.
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct target_instance { uint64_t start_jiffies; uint32_t hz; };
struct audit_event { uint32_t requester_pid, target_pid; uint64_t start_jiffies; uint32_t kind; };
struct audit_state { uint32_t requester_pid, target_pid; uint64_t start_jiffies; uint32_t kind; bool seen; };

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
        int outcome = ready_target == target && address ? ptrace_read(target, address, canary) : -2;
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
    if (!enabled && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        puts("LPS1_OFF_SAME_UID_PTRACE_CANARY_RECOVERED=PASS"); result = 0;
    } else if (enabled && WIFEXITED(status) && WEXITSTATUS(status) == 3 && audit.seen &&
               audit.requester_pid == (uint32_t)attacker && audit.target_pid == (uint32_t)target) {
        puts("LPS1_ON_SAME_UID_PTRACE_DENIED_AUDITED_CANARY_RECOVERY=0 PASS"); result = 0;
    } else {
        fprintf(stderr, "LPS1 oracle mismatch enabled=%d attacker_status=%d audit=%d requester=%u target=%u\n",
                enabled, status, audit.seen, audit.requester_pid, audit.target_pid);
    }
done:
    if (release_pipe[1] >= 0) { close(release_pipe[1]); stop_and_reap(attacker); }
    ring_buffer__free(ring); bpf_link__destroy(link); bpf_object__close(object); unlink(argv[3]);
    return result;
}
