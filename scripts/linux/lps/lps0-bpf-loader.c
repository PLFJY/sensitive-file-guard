// LPS0 capability-only loader. It attaches every LSM program in the supplied
// object and immediately destroys the links. No map is pinned and no policy is
// retained, so a successful result proves only BPF LSM load/attach capability.
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s PROGRAM.o\n", argv[0]);
        return 2;
    }
    struct bpf_object *object = bpf_object__open_file(argv[1], NULL);
    long error = libbpf_get_error(object);
    if (error) {
        fprintf(stderr, "open: %s\n", strerror((int)-error));
        return 1;
    }
    error = bpf_object__load(object);
    if (error) {
        fprintf(stderr, "load: %s\n", strerror((int)-error));
        bpf_object__close(object);
        return 1;
    }
    struct bpf_program *program;
    bpf_object__for_each_program(program, object) {
        struct bpf_link *link = bpf_program__attach_lsm(program);
        error = libbpf_get_error(link);
        if (error) {
            fprintf(stderr, "attach: %s\n", strerror((int)-error));
            bpf_object__close(object);
            return 1;
        }
        bpf_link__destroy(link);
    }
    bpf_object__close(object);
    puts("LPS0_BPF_LSM_LOAD_AND_ATTACH=PASS");
    return 0;
}
