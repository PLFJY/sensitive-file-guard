// LPS5 daemon-integrated same-UID oracle. The target is a disposable,
// root-owned synthetic Firefox-family authority which has already completed a
// real File Shield WebStorage open before its parent attacks its canary.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static int read_ready(const char *path, pid_t *pid, uint8_t canary[64], uintptr_t *address) {
    FILE *file = fopen(path, "r"); char hex[129], pointer[64];
    if (!file || fscanf(file, "%d %128s %63s", pid, hex, pointer) != 3) { if (file) fclose(file); return -1; }
    fclose(file); if (strlen(hex) != 128) return -1;
    for (size_t i = 0; i < 64; i++) if (sscanf(hex + i * 2, "%2hhx", &canary[i]) != 1) return -1;
    *address = (uintptr_t)strtoull(pointer, NULL, 0); return 0;
}
static int ptrace_read(pid_t pid, uintptr_t address, const uint8_t expected[64]) {
    if (ptrace(PTRACE_SEIZE, pid, NULL, NULL) < 0) return -1;
    if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) < 0 || waitpid(pid, NULL, 0) < 0) return -1;
    uint8_t got[64]; errno = 0;
    for (size_t i = 0; i < sizeof(got); i += sizeof(long)) { long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(address + i), NULL); if (word == -1 && errno) { ptrace(PTRACE_DETACH, pid, NULL, NULL); return -1; } memcpy(got + i, &word, sizeof(word)); }
    ptrace(PTRACE_DETACH, pid, NULL, NULL); return memcmp(got, expected, sizeof(got)) == 0 ? 1 : 0;
}
static int vm_read(pid_t pid, uintptr_t address, const uint8_t expected[64]) {
    uint8_t got[64]; struct iovec local={got,sizeof(got)}, remote={(void *)address,sizeof(got)};
    ssize_t n=process_vm_readv(pid,&local,1,&remote,1,0); return n == (ssize_t)sizeof(got) ? memcmp(got,expected,sizeof(got)) == 0 : -1;
}
static int vm_write(pid_t pid, uintptr_t address) {
    uint8_t byte=0xa5; struct iovec local={&byte,1}, remote={(void *)address,1};
    return process_vm_writev(pid,&local,1,&remote,1,0) == 1 ? 1 : -1;
}
static int proc_mem(pid_t pid, uintptr_t address, const uint8_t expected[64]) {
    char path[64]; uint8_t got[64]; snprintf(path,sizeof(path),"/proc/%d/mem",pid);
    int fd=open(path,O_RDONLY|O_CLOEXEC); if(fd<0) return -1; ssize_t n=pread(fd,got,sizeof(got),(off_t)address); close(fd);
    return n == (ssize_t)sizeof(got) ? memcmp(got,expected,sizeof(got)) == 0 : -1;
}
static int operation(const char *name, pid_t pid, uintptr_t address, const uint8_t expected[64]) {
    if (!strcmp(name,"ptrace")) return ptrace_read(pid,address,expected);
    if (!strcmp(name,"process_vm_readv")) return vm_read(pid,address,expected);
    if (!strcmp(name,"process_vm_writev")) return vm_write(pid,address);
    if (!strcmp(name,"proc_mem")) return proc_mem(pid,address,expected);
    return -2;
}
static void reap(pid_t pid) { if(pid>0) kill(pid,SIGTERM); if(pid>0) waitpid(pid,NULL,0); }

int main(int argc, char **argv) {
    if (argc != 6 || (strcmp(argv[1],"off") && strcmp(argv[1],"on")) || geteuid()!=0) return 2;
    const char *op=getenv("LPS_OPERATION"); if(!op) op="ptrace";
    const char *uid_text=getenv("TEST_UID"); if(!uid_text) return 2;
    struct passwd *pw=getpwuid((uid_t)strtoul(uid_text,NULL,10)); if(!pw || !pw->pw_uid) return 2;
    unlink(argv[3]); char admitted[512]; snprintf(admitted,sizeof(admitted),"%s.admitted",argv[3]); unlink(admitted);
    pid_t attacker=fork(); if(attacker<0) return 1;
    if(attacker==0) {
        if(setgroups(0,NULL)||setgid(pw->pw_gid)||setuid(pw->pw_uid)) _exit(126);
        pid_t target=fork(); if(target==0) { execl(argv[2],argv[2],"shield-authority",argv[3],argv[4],"--profile",argv[5],"20",NULL); _exit(127); }
        for(int i=0;i<300 && access(admitted,F_OK);i++) usleep(10000);
        pid_t ready=0; uint8_t canary[64]; uintptr_t address=0;
        int outcome = !access(admitted,F_OK) && !read_ready(argv[3],&ready,canary,&address) && ready==target ? operation(op,target,address,canary) : -2;
        // Keep requester and target live long enough for guardd's bounded
        // ring poll to resolve exact requester identity into persistent audit.
        usleep(600000); reap(target); _exit(outcome==1?0:outcome<0?3:4);
    }
    int status=0; waitpid(attacker,&status,0);
    if(!strcmp(argv[1],"off") && WIFEXITED(status) && WEXITSTATUS(status)==0) { puts("LPS5_DAEMON_OFF_CANARY_RECOVERED=PASS"); return 0; }
    if(!strcmp(argv[1],"on") && WIFEXITED(status) && WEXITSTATUS(status)==3) { puts("LPS5_DAEMON_ON_DENIED_CANARY_RECOVERY=0 PASS"); return 0; }
    fprintf(stderr,"daemon oracle mismatch op=%s mode=%s status=%d\n",op,argv[1],status); return 1;
}
