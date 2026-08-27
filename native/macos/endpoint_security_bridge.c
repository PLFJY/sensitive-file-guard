#include "endpoint_security_bridge.h"

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <mach/mach_time.h>
#include <string.h>
#include <stdlib.h>

struct guard_es_client {
    es_client_t *client;
};

// Public ES headers expose codesigning_flags but the SDK does not install the
// XNU cs_blobs header that names bit zero. Keep this one stable ABI bit local.
#define GUARD_CS_VALID 0x00000001u

static uint64_t guard_start_time_us(uint32_t message_version, const es_process_t *process) {
    if (message_version < 3 || process->start_time.tv_sec < 0 || process->start_time.tv_usec < 0) {
        return 0;
    }
    __uint128_t micros = (__uint128_t)process->start_time.tv_sec * 1000000
                           + (uint64_t)process->start_time.tv_usec;
    return micros > UINT64_MAX ? 0 : (uint64_t)micros;
}

static void guard_audit_identity(
    const audit_token_t *token,
    int32_t *pid,
    int32_t *pidversion) {
    *pid = audit_token_to_pid(*token);
    *pidversion = audit_token_to_pidversion(*token);
}

static void guard_normalize_process(
    uint32_t message_version,
    const es_process_t *process,
    guard_es_process_facts_t *normalized) {
    memset(normalized, 0, sizeof(*normalized));
    normalized->pid = audit_token_to_pid(process->audit_token);
    normalized->uid = audit_token_to_ruid(process->audit_token);
    normalized->gid = audit_token_to_rgid(process->audit_token);
    normalized->pidversion = audit_token_to_pidversion(process->audit_token);
    normalized->parent_pid = process->ppid;
    normalized->start_time_us = guard_start_time_us(message_version, process);
    if (message_version >= 4) {
        normalized->parent_identity_available = true;
        guard_audit_identity(
            &process->parent_audit_token,
            &normalized->parent_pid,
            &normalized->parent_pidversion);
        normalized->responsible_identity_available = true;
        guard_audit_identity(
            &process->responsible_audit_token,
            &normalized->responsible_pid,
            &normalized->responsible_pidversion);
    }
    const es_file_t *executable = process->executable;
    normalized->executable_dev = (uint64_t)executable->stat.st_dev;
    normalized->executable_ino = (uint64_t)executable->stat.st_ino;
    normalized->executable_mode = (uint32_t)executable->stat.st_mode;
    normalized->executable_owner_uid = executable->stat.st_uid;
    normalized->executable_size = (uint64_t)executable->stat.st_size;
    normalized->executable_mtime_ns =
        (int64_t)executable->stat.st_mtimespec.tv_sec * 1000000000
        + executable->stat.st_mtimespec.tv_nsec;
    normalized->executable_ctime_ns =
        (int64_t)executable->stat.st_ctimespec.tv_sec * 1000000000
        + executable->stat.st_ctimespec.tv_nsec;
    normalized->executable_path = (const uint8_t *)executable->path.data;
    normalized->executable_path_len = executable->path.length;
    normalized->executable_path_truncated = executable->path_truncated;
    normalized->code_signing_flags = process->codesigning_flags;
    normalized->code_signing_valid = (process->codesigning_flags & GUARD_CS_VALID) != 0;
    normalized->platform_binary = process->is_platform_binary;
    normalized->team_id = (const uint8_t *)process->team_id.data;
    normalized->team_id_len = process->team_id.length;
    normalized->signing_id = (const uint8_t *)process->signing_id.data;
    normalized->signing_id_len = process->signing_id.length;
    memcpy(normalized->cdhash, process->cdhash, sizeof(normalized->cdhash));
}

static int guard_new_client_result(es_new_client_result_t result) {
    switch (result) {
        case ES_NEW_CLIENT_RESULT_SUCCESS:
            return 0;
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            return 1;
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
            return 2;
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            return 3;
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            return 4;
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            return 5;
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            return 6;
    }
    return -1;
}

int guard_es_client_create(
    guard_es_client_t **client,
    guard_es_auth_open_callback_t callback,
    guard_es_process_callback_t process_callback,
    guard_es_namespace_callback_t namespace_callback,
    guard_es_sequence_callback_t sequence_callback,
    void *context) {
    if (client == NULL || sequence_callback == NULL ||
        (callback == NULL && process_callback == NULL && namespace_callback == NULL)) {
        return 1;
    }
    *client = NULL;
    guard_es_client_t *wrapper = calloc(1, sizeof(*wrapper));
    if (wrapper == NULL) {
        return 2;
    }
    es_new_client_result_t result = es_new_client(&wrapper->client, ^(
        es_client_t *es_client, const es_message_t *message) {
        uint32_t stable_event_kind = 0;
        switch (message->event_type) {
            case ES_EVENT_TYPE_AUTH_OPEN: stable_event_kind = 1; break;
            case ES_EVENT_TYPE_NOTIFY_FORK: stable_event_kind = 2; break;
            case ES_EVENT_TYPE_NOTIFY_EXEC: stable_event_kind = 3; break;
            case ES_EVENT_TYPE_NOTIFY_EXIT: stable_event_kind = 4; break;
            case ES_EVENT_TYPE_AUTH_LINK: stable_event_kind = 5; break;
            case ES_EVENT_TYPE_AUTH_RENAME: stable_event_kind = 6; break;
            default: break;
        }
        sequence_callback(context, stable_event_kind, message->version >= 2,
                          message->version >= 2 ? message->seq_num : 0,
                          message->version >= 4,
                          message->version >= 4 ? message->global_seq_num : 0);
        if (message->event_type == ES_EVENT_TYPE_NOTIFY_FORK) {
            if (process_callback == NULL) return;
            guard_es_process_facts_t child;
            guard_es_process_facts_t parent;
            guard_normalize_process(message->version, message->event.fork.child, &child);
            guard_normalize_process(message->version, message->process, &parent);
            process_callback(context, 1, &child, &parent);
            return;
        }
        if (message->event_type == ES_EVENT_TYPE_NOTIFY_EXEC) {
            if (process_callback == NULL) return;
            guard_es_process_facts_t target;
            guard_normalize_process(message->version, message->event.exec.target, &target);
            process_callback(context, 2, &target, NULL);
            return;
        }
        if (message->event_type == ES_EVENT_TYPE_NOTIFY_EXIT) {
            if (process_callback == NULL) return;
            guard_es_process_facts_t exiting;
            guard_normalize_process(message->version, message->process, &exiting);
            process_callback(context, 3, &exiting, NULL);
            return;
        }
        if (message->action_type == ES_ACTION_TYPE_AUTH &&
            (message->event_type == ES_EVENT_TYPE_AUTH_LINK ||
             message->event_type == ES_EVENT_TYPE_AUTH_RENAME)) {
            if (namespace_callback == NULL) return;
            guard_es_namespace_event_t normalized;
            memset(&normalized, 0, sizeof(normalized));
            normalized.deadline = message->deadline;
            const es_file_t *source = NULL;
            if (message->event_type == ES_EVENT_TYPE_AUTH_LINK) {
                const es_event_link_t *link = &message->event.link;
                normalized.operation = 1;
                source = link->source;
                normalized.destination_dir_path = (const uint8_t *)link->target_dir->path.data;
                normalized.destination_dir_path_len = link->target_dir->path.length;
                normalized.destination_dir_path_truncated = link->target_dir->path_truncated;
                normalized.destination_name = (const uint8_t *)link->target_filename.data;
                normalized.destination_name_len = link->target_filename.length;
            } else {
                const es_event_rename_t *rename = &message->event.rename;
                normalized.operation = 2;
                source = rename->source;
                if (rename->destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
                    const es_file_t *destination = rename->destination.existing_file;
                    normalized.destination_existing = true;
                    normalized.destination_dev = (uint64_t)destination->stat.st_dev;
                    normalized.destination_ino = (uint64_t)destination->stat.st_ino;
                    normalized.destination_existing_path =
                        (const uint8_t *)destination->path.data;
                    normalized.destination_existing_path_len = destination->path.length;
                    normalized.destination_existing_path_truncated = destination->path_truncated;
                } else {
                    const es_file_t *dir = rename->destination.new_path.dir;
                    normalized.destination_dir_path = (const uint8_t *)dir->path.data;
                    normalized.destination_dir_path_len = dir->path.length;
                    normalized.destination_dir_path_truncated = dir->path_truncated;
                    normalized.destination_name =
                        (const uint8_t *)rename->destination.new_path.filename.data;
                    normalized.destination_name_len =
                        rename->destination.new_path.filename.length;
                }
            }
            normalized.source_dev = (uint64_t)source->stat.st_dev;
            normalized.source_ino = (uint64_t)source->stat.st_ino;
            normalized.source_path = (const uint8_t *)source->path.data;
            normalized.source_path_len = source->path.length;
            normalized.source_path_truncated = source->path_truncated;
            guard_normalize_process(message->version, message->process, &normalized.process);
            namespace_callback(context, es_client, message, &normalized);
            return;
        }
        if (message->action_type != ES_ACTION_TYPE_AUTH ||
            message->event_type != ES_EVENT_TYPE_AUTH_OPEN) {
            if (callback != NULL) callback(context, es_client, message, NULL);
            return;
        }
        if (callback == NULL) return;
        const es_event_open_t *open_event = &message->event.open;
        const es_file_t *target = open_event->file;
        guard_es_auth_open_event_t normalized;
        memset(&normalized, 0, sizeof(normalized));
        normalized = (guard_es_auth_open_event_t){
            .requested_flags = (uint32_t)open_event->fflag,
            .deadline = message->deadline,
            .target_dev = (uint64_t)target->stat.st_dev,
            .target_ino = (uint64_t)target->stat.st_ino,
            .target_path = (const uint8_t *)target->path.data,
            .target_path_len = target->path.length,
            .target_path_truncated = target->path_truncated,
        };
        guard_normalize_process(message->version, message->process, &normalized.process);
        callback(context, es_client, message, &normalized);
    });
    int stable_result = guard_new_client_result(result);
    if (stable_result != 0) {
        free(wrapper);
        return stable_result;
    }
    *client = wrapper;
    return 0;
}

int guard_es_client_subscribe_authorization(guard_es_client_t *client) {
    if (client == NULL || client->client == NULL) {
        return -1;
    }
    es_event_type_t events[] = {
        ES_EVENT_TYPE_AUTH_OPEN,
        ES_EVENT_TYPE_AUTH_LINK,
        ES_EVENT_TYPE_AUTH_RENAME,
    };
    return es_subscribe(client->client, events, 3) == ES_RETURN_SUCCESS ? 0 : -1;
}

int guard_es_client_subscribe_process_graph(guard_es_client_t *client) {
    if (client == NULL || client->client == NULL) return -1;
    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_EXIT,
    };
    return es_subscribe(client->client, events, 3) == ES_RETURN_SUCCESS ? 0 : -1;
}

int guard_es_client_configure_target_paths(
    guard_es_client_t *client,
    const guard_es_target_path_t *paths,
    size_t path_count) {
    if (client == NULL || client->client == NULL || (path_count > 0 && paths == NULL)) {
        return -1;
    }
    // Apple requires this setup before AUTH subscriptions: default target
    // muting must not become the inverted selection set.
    if (es_unsubscribe_all(client->client) != ES_RETURN_SUCCESS) return -1;
    if (es_muting_inverted(client->client, ES_MUTE_INVERSION_TYPE_TARGET_PATH) == ES_MUTE_INVERTED &&
        es_invert_muting(client->client, ES_MUTE_INVERSION_TYPE_TARGET_PATH) != ES_RETURN_SUCCESS) {
        return -1;
    }
    if (es_unmute_all_target_paths(client->client) != ES_RETURN_SUCCESS ||
        es_invert_muting(client->client, ES_MUTE_INVERSION_TYPE_TARGET_PATH) != ES_RETURN_SUCCESS) {
        return -1;
    }
    for (size_t i = 0; i < path_count; ++i) {
        if (paths[i].path == NULL || paths[i].path[0] == '\0') return -1;
        es_mute_path_type_t type = paths[i].prefix
            ? ES_MUTE_PATH_TYPE_TARGET_PREFIX
            : ES_MUTE_PATH_TYPE_TARGET_LITERAL;
        if (es_mute_path(client->client, paths[i].path, type) != ES_RETURN_SUCCESS) return -1;
    }
    return guard_es_client_subscribe_authorization(client);
}

int guard_es_client_update_target_paths(
    guard_es_client_t *client,
    const guard_es_target_path_t *paths,
    size_t path_count,
    bool mute) {
    if (client == NULL || client->client == NULL || (path_count > 0 && paths == NULL)) {
        return -1;
    }
    for (size_t i = 0; i < path_count; ++i) {
        if (paths[i].path == NULL || paths[i].path[0] == '\0') return -1;
        es_mute_path_type_t type = paths[i].prefix
            ? ES_MUTE_PATH_TYPE_TARGET_PREFIX
            : ES_MUTE_PATH_TYPE_TARGET_LITERAL;
        es_return_t result = mute
            ? es_mute_path(client->client, paths[i].path, type)
            : es_unmute_path(client->client, paths[i].path, type);
        if (result != ES_RETURN_SUCCESS) return -1;
    }
    return 0;
}

bool guard_es_client_target_path_inversion_active(const guard_es_client_t *client) {
    return client != NULL && client->client != NULL &&
        es_muting_inverted(client->client, ES_MUTE_INVERSION_TYPE_TARGET_PATH) == ES_MUTE_INVERTED;
}

int guard_es_client_delete(guard_es_client_t *client) {
    if (client == NULL) {
        return 0;
    }
    int result = es_delete_client(client->client) == ES_RETURN_SUCCESS ? 0 : -1;
    free(client);
    return result;
}

void guard_es_message_retain(const void *message) {
    es_retain_message((const es_message_t *)message);
}

void guard_es_message_release(const void *message) {
    es_release_message((const es_message_t *)message);
}

int guard_es_respond_flags(
    const void *client,
    const void *message,
    uint32_t authorized_flags) {
    es_respond_result_t result = es_respond_flags_result(
        (es_client_t *)client,
        (const es_message_t *)message,
        authorized_flags,
        false);
    switch (result) {
        case ES_RESPOND_RESULT_SUCCESS:
            return 0;
        case ES_RESPOND_RESULT_ERR_INVALID_ARGUMENT:
            return 1;
        case ES_RESPOND_RESULT_ERR_INTERNAL:
            return 2;
        case ES_RESPOND_RESULT_NOT_FOUND:
            return 3;
        case ES_RESPOND_RESULT_ERR_DUPLICATE_RESPONSE:
            return 4;
        case ES_RESPOND_RESULT_ERR_EVENT_TYPE:
            return 5;
    }
    return -1;
}

int guard_es_respond_auth(
    const void *client,
    const void *message,
    bool allow) {
    es_respond_result_t result = es_respond_auth_result(
        (es_client_t *)client,
        (const es_message_t *)message,
        allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY,
        false);
    switch (result) {
        case ES_RESPOND_RESULT_SUCCESS: return 0;
        case ES_RESPOND_RESULT_ERR_INVALID_ARGUMENT: return 1;
        case ES_RESPOND_RESULT_ERR_INTERNAL: return 2;
        case ES_RESPOND_RESULT_NOT_FOUND: return 3;
        case ES_RESPOND_RESULT_ERR_DUPLICATE_RESPONSE: return 4;
        case ES_RESPOND_RESULT_ERR_EVENT_TYPE: return 5;
    }
    return -1;
}

uint64_t guard_mach_absolute_time(void) {
    return mach_absolute_time();
}

uint64_t guard_mach_ticks_to_nanos(uint64_t ticks) {
    mach_timebase_info_data_t info;
    if (mach_timebase_info(&info) != KERN_SUCCESS || info.denom == 0) {
        return 0;
    }
    __uint128_t nanos = (__uint128_t)ticks * info.numer / info.denom;
    return nanos > UINT64_MAX ? UINT64_MAX : (uint64_t)nanos;
}
