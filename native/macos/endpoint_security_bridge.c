#include "endpoint_security_bridge.h"

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <mach/mach_time.h>
#include <stdlib.h>

struct guard_es_client {
    es_client_t *client;
};

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
    void *context) {
    if (client == NULL || callback == NULL) {
        return 1;
    }
    *client = NULL;
    guard_es_client_t *wrapper = calloc(1, sizeof(*wrapper));
    if (wrapper == NULL) {
        return 2;
    }
    es_new_client_result_t result = es_new_client(&wrapper->client, ^(
        es_client_t *es_client, const es_message_t *message) {
        if (message->action_type != ES_ACTION_TYPE_AUTH ||
            message->event_type != ES_EVENT_TYPE_AUTH_OPEN) {
            callback(context, es_client, message, NULL);
            return;
        }
        const es_process_t *process = message->process;
        const es_event_open_t *open_event = &message->event.open;
        const es_file_t *target = open_event->file;
        const es_file_t *executable = process->executable;
        guard_es_auth_open_event_t normalized = {
            .requested_flags = (uint32_t)open_event->fflag,
            .deadline = message->deadline,
            .pid = audit_token_to_pid(process->audit_token),
            .uid = audit_token_to_ruid(process->audit_token),
            .pidversion = audit_token_to_pidversion(process->audit_token),
            .target_dev = (uint64_t)target->stat.st_dev,
            .target_ino = (uint64_t)target->stat.st_ino,
            .target_path = (const uint8_t *)target->path.data,
            .target_path_len = target->path.length,
            .target_path_truncated = target->path_truncated,
            .executable_dev = (uint64_t)executable->stat.st_dev,
            .executable_ino = (uint64_t)executable->stat.st_ino,
            .executable_path = (const uint8_t *)executable->path.data,
            .executable_path_len = executable->path.length,
            .executable_path_truncated = executable->path_truncated,
        };
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

int guard_es_client_subscribe_auth_open(guard_es_client_t *client) {
    if (client == NULL || client->client == NULL) {
        return -1;
    }
    es_event_type_t event = ES_EVENT_TYPE_AUTH_OPEN;
    return es_subscribe(client->client, &event, 1) == ES_RETURN_SUCCESS ? 0 : -1;
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
