#ifndef GUARD_CODE_SIGNATURE_BRIDGE_H
#define GUARD_CODE_SIGNATURE_BRIDGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    bool valid;
    char team_id[128];
    char signing_id[256];
    char leaf_certificate_sha1[41];
    uint8_t cdhash[20];
    size_t cdhash_len;
} guard_code_signature_info_t;

int guard_code_signature_inspect(
    const char *path,
    guard_code_signature_info_t *info,
    char *error,
    size_t error_len);

#endif
