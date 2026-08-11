#ifndef GUARD_XPC_BRIDGE_H
#define GUARD_XPC_BRIDGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct guard_xpc_server guard_xpc_server_t;

typedef bool (*guard_xpc_peer_callback_t)(uint32_t euid, void *context);
typedef bool (*guard_xpc_request_callback_t)(const uint8_t *request,
                                             size_t request_length,
                                             uint32_t euid,
                                             const uint8_t **response,
                                             size_t *response_length,
                                             void *context);
typedef void (*guard_xpc_response_free_t)(const uint8_t *response,
                                          size_t response_length,
                                          void *context);

// Creates the named listener provisioned for the Endpoint Security extension
// by the matching NSEndpointSecurityMachServiceName value.
guard_xpc_server_t *guard_xpc_server_create(
    const char *service_name,
    const char *client_code_signing_requirement,
    size_t maximum_request_bytes,
    size_t maximum_concurrent_requests,
    guard_xpc_peer_callback_t peer_callback,
    guard_xpc_request_callback_t request_callback,
    guard_xpc_response_free_t response_free,
    void *context,
    char *error_buffer,
    size_t error_buffer_length);

void guard_xpc_server_activate(guard_xpc_server_t *server);
void guard_xpc_server_run(guard_xpc_server_t *server);
void guard_xpc_server_destroy(guard_xpc_server_t *server);

// Makes one bounded request to the explicit Endpoint Security Mach service.
// The returned bytes are owned by the caller and must be released with
// guard_xpc_bytes_free.
bool guard_xpc_request(const char *service_name,
                       const char *server_code_signing_requirement,
                       const uint8_t *request,
                       size_t request_length,
                       uint64_t timeout_milliseconds,
                       uint8_t **response,
                       size_t *response_length,
                       char *error_buffer,
                       size_t error_buffer_length);

void guard_xpc_bytes_free(uint8_t *bytes);

// Uses Security.framework's parser so malformed requirement strings fail at
// startup rather than weakening peer authentication.
bool guard_code_signing_requirement_is_valid(const char *requirement,
                                             char *error_buffer,
                                             size_t error_buffer_length);

#endif
