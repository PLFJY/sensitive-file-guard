#ifndef GUARD_LOCAL_AUTH_BRIDGE_H
#define GUARD_LOCAL_AUTH_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

typedef enum guard_local_auth_result {
    GUARD_LOCAL_AUTH_SUCCESS = 0,
    GUARD_LOCAL_AUTH_CANCELLED = 1,
    GUARD_LOCAL_AUTH_TIMED_OUT = 2,
    GUARD_LOCAL_AUTH_UNAVAILABLE = 3,
    GUARD_LOCAL_AUTH_FAILED = 4,
} guard_local_auth_result_t;

guard_local_auth_result_t guard_local_authenticate(
    const char *localized_reason,
    uint64_t timeout_milliseconds,
    char *error_buffer,
    size_t error_buffer_length);

#endif
