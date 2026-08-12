#ifndef GUARD_ENDPOINT_SECURITY_BRIDGE_H
#define GUARD_ENDPOINT_SECURITY_BRIDGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct guard_es_client guard_es_client_t;

typedef struct {
    int32_t pid;
    uint32_t uid;
    uint32_t gid;
    int32_t pidversion;
    int32_t parent_pid;
    int32_t parent_pidversion;
    bool parent_identity_available;
    int32_t responsible_pid;
    int32_t responsible_pidversion;
    bool responsible_identity_available;
    uint64_t start_time_us;
    uint64_t executable_dev;
    uint64_t executable_ino;
    uint32_t executable_mode;
    uint32_t executable_owner_uid;
    uint64_t executable_size;
    int64_t executable_mtime_ns;
    int64_t executable_ctime_ns;
    const uint8_t *executable_path;
    size_t executable_path_len;
    bool executable_path_truncated;
    uint32_t code_signing_flags;
    bool code_signing_valid;
    bool platform_binary;
    const uint8_t *team_id;
    size_t team_id_len;
    const uint8_t *signing_id;
    size_t signing_id_len;
    uint8_t cdhash[20];
} guard_es_process_facts_t;

typedef struct {
    uint32_t requested_flags;
    uint64_t deadline;
    uint64_t target_dev;
    uint64_t target_ino;
    const uint8_t *target_path;
    size_t target_path_len;
    bool target_path_truncated;
    guard_es_process_facts_t process;
} guard_es_auth_open_event_t;

typedef struct {
    uint32_t operation;
    uint64_t deadline;
    uint64_t source_dev;
    uint64_t source_ino;
    const uint8_t *source_path;
    size_t source_path_len;
    bool source_path_truncated;
    bool destination_existing;
    uint64_t destination_dev;
    uint64_t destination_ino;
    const uint8_t *destination_dir_path;
    size_t destination_dir_path_len;
    bool destination_dir_path_truncated;
    const uint8_t *destination_name;
    size_t destination_name_len;
    const uint8_t *destination_existing_path;
    size_t destination_existing_path_len;
    bool destination_existing_path_truncated;
    guard_es_process_facts_t process;
} guard_es_namespace_event_t;

typedef void (*guard_es_auth_open_callback_t)(
    void *context,
    const void *client,
    const void *message,
    const guard_es_auth_open_event_t *event);

typedef void (*guard_es_process_callback_t)(
    void *context,
    uint32_t event_kind,
    const guard_es_process_facts_t *process,
    const guard_es_process_facts_t *related_process);

typedef void (*guard_es_namespace_callback_t)(
    void *context,
    const void *client,
    const void *message,
    const guard_es_namespace_event_t *event);

typedef void (*guard_es_sequence_callback_t)(
    void *context,
    uint32_t event_kind,
    bool has_sequence,
    uint64_t sequence,
    bool has_global_sequence,
    uint64_t global_sequence);

int guard_es_client_create(
    guard_es_client_t **client,
    guard_es_auth_open_callback_t callback,
    guard_es_process_callback_t process_callback,
    guard_es_namespace_callback_t namespace_callback,
    guard_es_sequence_callback_t sequence_callback,
    void *context);
int guard_es_client_subscribe_required(guard_es_client_t *client);
int guard_es_client_delete(guard_es_client_t *client);

void guard_es_message_retain(const void *message);
void guard_es_message_release(const void *message);
int guard_es_respond_flags(
    const void *client,
    const void *message,
    uint32_t authorized_flags);
int guard_es_respond_auth(
    const void *client,
    const void *message,
    bool allow);

uint64_t guard_mach_absolute_time(void);
uint64_t guard_mach_ticks_to_nanos(uint64_t ticks);

#endif
