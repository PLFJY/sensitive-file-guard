#ifndef GUARD_ENDPOINT_SECURITY_BRIDGE_H
#define GUARD_ENDPOINT_SECURITY_BRIDGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct guard_es_client guard_es_client_t;

typedef struct {
    uint32_t requested_flags;
    uint64_t deadline;
    int32_t pid;
    uint32_t uid;
    int32_t pidversion;
    uint64_t target_dev;
    uint64_t target_ino;
    const uint8_t *target_path;
    size_t target_path_len;
    bool target_path_truncated;
    uint64_t executable_dev;
    uint64_t executable_ino;
    const uint8_t *executable_path;
    size_t executable_path_len;
    bool executable_path_truncated;
} guard_es_auth_open_event_t;

typedef void (*guard_es_auth_open_callback_t)(
    void *context,
    const void *client,
    const void *message,
    const guard_es_auth_open_event_t *event);

int guard_es_client_create(
    guard_es_client_t **client,
    guard_es_auth_open_callback_t callback,
    void *context);
int guard_es_client_subscribe_auth_open(guard_es_client_t *client);
int guard_es_client_delete(guard_es_client_t *client);

void guard_es_message_retain(const void *message);
void guard_es_message_release(const void *message);
int guard_es_respond_flags(
    const void *client,
    const void *message,
    uint32_t authorized_flags);

uint64_t guard_mach_absolute_time(void);
uint64_t guard_mach_ticks_to_nanos(uint64_t ticks);

#endif
