#!/usr/bin/env bash
# Minimal fanotify FID topology probe: create FAN_CLASS_NOTIF|FAN_REPORT_FID
# group, mark a dir with FAN_MOVE|FAN_EVENT_ON_CHILD, mv a file, dump raw
# event bytes so the Rust parser can be validated against the real kernel.
set -euo pipefail
cat > /tmp/fid-probe.c <<'EOF'
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/fanotify.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

static void dump(const unsigned char* p, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x ", p[i]);
    printf("\n");
}

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s DIR\n", argv[0]); return 1; }
    int fd = syscall(SYS_fanotify_init, FAN_CLOEXEC | FAN_REPORT_FID, 0);
    if (fd < 0) { printf("init errno=%d (%s)\n", errno, strerror(errno)); return 1; }
    printf("group fd=%d\n", fd);
    int rc = syscall(SYS_fanotify_mark, fd, FAN_MARK_ADD,
                     FAN_MOVE | FAN_EVENT_ON_CHILD, AT_FDCWD, argv[1]);
    if (rc < 0) { printf("mark errno=%d (%s)\n", errno, strerror(errno)); return 1; }
    printf("marked %s\n", argv[1]);
    // Also mark the destination dir so MOVED_TO fires too.
    if (argc > 2) {
        rc = syscall(SYS_fanotify_mark, fd, FAN_MARK_ADD,
                     FAN_MOVE | FAN_EVENT_ON_CHILD, AT_FDCWD, argv[2]);
        if (rc < 0) printf("mark dest errno=%d (%s)\n", errno, strerror(errno));
        else printf("marked %s\n", argv[2]);
    }
    printf("waiting for events (mv a file into/out of the dirs)...\n");
    char buf[65536];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) { printf("read errno=%d (%s)\n", errno, strerror(errno)); break; }
        printf("READ %zd bytes:\n", n);
        dump((unsigned char*)buf, n);
        if (n < (ssize_t)sizeof(struct fanotify_event_metadata)) continue;
        struct fanotify_event_metadata* meta = (struct fanotify_event_metadata*)buf;
        printf("  event_len=%u metadata_len=%u mask=0x%llx fd=%d\n",
               meta->event_len, meta->metadata_len,
               (unsigned long long)meta->mask, meta->fd);
        if (meta->event_len > sizeof(struct fanotify_event_metadata)) {
            size_t info_off = meta->metadata_len;
            size_t info_len = meta->event_len - meta->metadata_len;
            printf("  info region [%zu..%zu):\n", info_off, meta->event_len);
            dump((unsigned char*)buf + info_off, info_len);
        }
        fflush(stdout);
    }
    return 0;
}
EOF
cc -o /tmp/fid-probe /tmp/fid-probe.c
echo COMPILED
