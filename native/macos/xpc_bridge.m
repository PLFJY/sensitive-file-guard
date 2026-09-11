#import "xpc_bridge.h"

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dispatch/dispatch.h>
#import <fcntl.h>
#import <limits.h>
#import <stdatomic.h>
#import <sys/stat.h>
#import <unistd.h>
#import <xpc/xpc.h>

static const char *GuardRequestKey = "request";
static const char *GuardResponseKey = "response";
static const char *GuardErrorKey = "error";

static void guard_copy_error(char *buffer, size_t length, NSString *message) {
    if (buffer == NULL || length == 0) {
        return;
    }
    const char *utf8 = message.UTF8String;
    if (utf8 == NULL) {
        utf8 = "unknown macOS XPC error";
    }
    snprintf(buffer, length, "%s", utf8);
}

static NSString *GuardOSStatusMessage(OSStatus status) {
    CFStringRef message = SecCopyErrorMessageString(status, NULL);
    if (message == NULL) {
        return [NSString stringWithFormat:@"Security.framework error %d", (int)status];
    }
    return CFBridgingRelease(message);
}

static SecRequirementRef GuardCreateRequirement(const char *text,
                                                 char *errorBuffer,
                                                 size_t errorBufferLength) {
    if (text == NULL) {
        guard_copy_error(errorBuffer, errorBufferLength,
                         @"code-signing requirement is missing");
        return NULL;
    }
    NSString *requirementText = [NSString stringWithUTF8String:text];
    if (requirementText == nil) {
        guard_copy_error(errorBuffer, errorBufferLength,
                         @"code-signing requirement is not UTF-8");
        return NULL;
    }
    SecRequirementRef requirement = NULL;
    OSStatus status = SecRequirementCreateWithString(
        (__bridge CFStringRef)requirementText, kSecCSDefaultFlags, &requirement);
    if (status != errSecSuccess) {
        guard_copy_error(errorBuffer, errorBufferLength,
                         GuardOSStatusMessage(status));
        return NULL;
    }
    return requirement;
}

// A self-signed Endpoint Security development build has no Apple provisioning
// profile and is therefore not dynamically trusted even when SIP-off permits
// it to run. Bind the sender through the kernel-supplied XPC audit token, then
// validate the complete static signature against the exact pinned requirement.
static BOOL GuardValidateSelfUseMessage(xpc_object_t message,
                                        SecRequirementRef requirement,
                                        NSString **diagnostic) {
    if (xpc_get_type(message) != XPC_TYPE_DICTIONARY || requirement == NULL) {
        if (diagnostic != NULL) {
            *diagnostic = @"message or signing requirement is invalid";
        }
        return NO;
    }

    SecCodeRef dynamicCode = NULL;
    OSStatus status = SecCodeCreateWithXPCMessage(
        message, kSecCSDefaultFlags, &dynamicCode);
    if (status != errSecSuccess) {
        if (diagnostic != NULL) {
            *diagnostic = GuardOSStatusMessage(status);
        }
        return NO;
    }

    SecStaticCodeRef staticCode = NULL;
    status = SecCodeCopyStaticCode(dynamicCode, kSecCSDefaultFlags, &staticCode);
    CFRelease(dynamicCode);
    if (status != errSecSuccess) {
        if (diagnostic != NULL) {
            *diagnostic = GuardOSStatusMessage(status);
        }
        return NO;
    }

    CFDictionaryRef signingInformation = NULL;
    status = SecCodeCopySigningInformation(
        staticCode, kSecCSDefaultFlags, &signingInformation);
    if (status != errSecSuccess || signingInformation == NULL) {
        CFRelease(staticCode);
        if (diagnostic != NULL) {
            *diagnostic = GuardOSStatusMessage(status);
        }
        return NO;
    }
    CFURLRef executableURL = CFDictionaryGetValue(
        signingInformation, kSecCodeInfoMainExecutable);
    NSString *executablePath = executableURL == NULL
        ? nil
        : [(__bridge NSURL *)executableURL path];
    char canonicalPath[PATH_MAX];
    BOOL hasCanonicalPath = executablePath != nil && executablePath.isAbsolutePath &&
        realpath(executablePath.fileSystemRepresentation, canonicalPath) != NULL;
    CFRelease(signingInformation);
    if (!hasCanonicalPath) {
        CFRelease(staticCode);
        if (diagnostic != NULL) {
            *diagnostic = @"peer executable has no canonical local path";
        }
        return NO;
    }
    int executable = open(canonicalPath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat before = {0};
    if (executable < 0 || fstat(executable, &before) != 0 ||
        !S_ISREG(before.st_mode) || before.st_dev == 0 || before.st_ino == 0 ||
        (before.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        if (executable >= 0) {
            close(executable);
        }
        CFRelease(staticCode);
        if (diagnostic != NULL) {
            *diagnostic = @"peer executable file identity or permissions are unsafe";
        }
        return NO;
    }

    CFErrorRef validationError = NULL;
    status = SecStaticCodeCheckValidityWithErrors(
        staticCode, kSecCSStrictValidate | kSecCSCheckAllArchitectures,
        requirement, &validationError);
    CFRelease(staticCode);
    struct stat after = {0};
    BOOL stableFileIdentity = lstat(canonicalPath, &after) == 0 &&
        before.st_dev == after.st_dev && before.st_ino == after.st_ino;
    close(executable);
    if (!stableFileIdentity && status == errSecSuccess) {
        status = errSecCSStaticCodeChanged;
    }
    if (status == errSecSuccess) {
        if (validationError != NULL) {
            CFRelease(validationError);
        }
        return YES;
    }
    if (diagnostic != NULL) {
        if (validationError != NULL) {
            *diagnostic = CFBridgingRelease(CFErrorCopyDescription(validationError));
        } else {
            *diagnostic = GuardOSStatusMessage(status);
        }
    }
    if (validationError != NULL) {
        CFRelease(validationError);
    }
    return NO;
}

struct guard_xpc_server {
    xpc_connection_t listener;
    dispatch_queue_t queue;
    SecRequirementRef client_requirement;
    guard_xpc_validation_mode_t validation_mode;
    size_t maximum_request_bytes;
    size_t maximum_concurrent_requests;
    guard_xpc_peer_callback_t peer_callback;
    guard_xpc_request_callback_t request_callback;
    guard_xpc_response_free_t response_free;
    void *context;
    _Atomic size_t active_requests;
    _Atomic bool activated;
};

static void GuardReplyError(xpc_object_t request, xpc_connection_t peer,
                            const char *error) {
    xpc_object_t reply = xpc_dictionary_create_reply(request);
    if (reply == NULL) {
        return;
    }
    xpc_dictionary_set_string(reply, GuardErrorKey, error);
    xpc_connection_send_message(peer, reply);
}

static void GuardHandleRequest(guard_xpc_server_t *server,
                               xpc_connection_t peer,
                               xpc_object_t event,
                               uint32_t peerEuid) {
    if (xpc_get_type(event) != XPC_TYPE_DICTIONARY) {
        return;
    }
    if (server->validation_mode == GUARD_XPC_VALIDATION_SELF_USE_STATIC) {
        NSString *diagnostic = nil;
        if (!GuardValidateSelfUseMessage(event, server->client_requirement,
                                         &diagnostic)) {
            NSLog(@"Guard XPC rejected self-use client: %@",
                  diagnostic ?: @"signature validation failed");
            GuardReplyError(event, peer, "XPC client authentication failed");
            xpc_connection_cancel(peer);
            return;
        }
    }

    size_t requestLength = 0;
    const void *requestBytes =
        xpc_dictionary_get_data(event, GuardRequestKey, &requestLength);
    if (requestBytes == NULL || requestLength > server->maximum_request_bytes) {
        GuardReplyError(event, peer, "request exceeds guard-ipc MAX_REQUEST_BYTES");
        return;
    }

    size_t previous = atomic_fetch_add_explicit(
        &server->active_requests, 1, memory_order_acq_rel);
    if (previous >= server->maximum_concurrent_requests) {
        atomic_fetch_sub_explicit(&server->active_requests, 1,
                                  memory_order_acq_rel);
        GuardReplyError(event, peer, "XPC request concurrency limit reached");
        return;
    }

    const uint8_t *responseBytes = NULL;
    size_t responseLength = 0;
    bool handled = server->request_callback(
        requestBytes, requestLength, peerEuid, &responseBytes, &responseLength,
        server->context);
    xpc_object_t reply = xpc_dictionary_create_reply(event);
    if (reply != NULL) {
        if (handled && responseBytes != NULL) {
            xpc_dictionary_set_data(reply, GuardResponseKey, responseBytes,
                                    responseLength);
        } else {
            xpc_dictionary_set_string(reply, GuardErrorKey,
                                      "Guard XPC request handler failed closed");
        }
        xpc_connection_send_message(peer, reply);
    }
    if (handled && responseBytes != NULL) {
        server->response_free(responseBytes, responseLength, server->context);
    }
    atomic_fetch_sub_explicit(&server->active_requests, 1,
                              memory_order_acq_rel);
}

static void GuardAcceptPeer(guard_xpc_server_t *server, xpc_object_t event) {
    if (xpc_get_type(event) != XPC_TYPE_CONNECTION) {
        return;
    }
    xpc_connection_t peer = event;
    uint32_t peerEuid = xpc_connection_get_euid(peer);
    if (!server->peer_callback(peerEuid, server->context)) {
        xpc_connection_cancel(peer);
        return;
    }

    xpc_connection_set_target_queue(peer, server->queue);
    xpc_connection_set_event_handler(peer, ^(xpc_object_t peerEvent) {
      GuardHandleRequest(server, peer, peerEvent, peerEuid);
    });
    xpc_connection_resume(peer);
}

guard_xpc_server_t *guard_xpc_server_create(
    const char *service_name,
    const char *client_code_signing_requirement,
    guard_xpc_validation_mode_t validation_mode,
    size_t maximum_request_bytes,
    size_t maximum_concurrent_requests,
    guard_xpc_peer_callback_t peer_callback,
    guard_xpc_request_callback_t request_callback,
    guard_xpc_response_free_t response_free,
    void *context,
    char *error_buffer,
    size_t error_buffer_length) {
    if (service_name == NULL || client_code_signing_requirement == NULL ||
        maximum_request_bytes == 0 || maximum_concurrent_requests == 0 ||
        peer_callback == NULL || request_callback == NULL ||
        response_free == NULL ||
        (validation_mode != GUARD_XPC_VALIDATION_DYNAMIC &&
         validation_mode != GUARD_XPC_VALIDATION_SELF_USE_STATIC)) {
        guard_copy_error(error_buffer, error_buffer_length,
                         @"invalid Guard XPC server configuration");
        return NULL;
    }

    SecRequirementRef parsed = GuardCreateRequirement(
        client_code_signing_requirement, error_buffer, error_buffer_length);
    if (parsed == NULL) {
        return NULL;
    }
    guard_xpc_server_t *server = calloc(1, sizeof(*server));
    if (server == NULL) {
        CFRelease(parsed);
        guard_copy_error(error_buffer, error_buffer_length,
                         @"could not allocate Guard XPC server");
        return NULL;
    }
    server->queue = dispatch_queue_create("top.plfjy.guard.xpc", DISPATCH_QUEUE_CONCURRENT);
    server->client_requirement = parsed;
    server->validation_mode = validation_mode;
    server->maximum_request_bytes = maximum_request_bytes;
    server->maximum_concurrent_requests = maximum_concurrent_requests;
    server->peer_callback = peer_callback;
    server->request_callback = request_callback;
    server->response_free = response_free;
    server->context = context;
    atomic_init(&server->active_requests, 0);
    atomic_init(&server->activated, false);

    server->listener = xpc_connection_create_mach_service(
        service_name, server->queue, XPC_CONNECTION_MACH_SERVICE_LISTENER);
    if (server->listener == NULL) {
        CFRelease(parsed);
        free(server);
        guard_copy_error(error_buffer, error_buffer_length,
                         @"could not create Guard XPC Mach service listener");
        return NULL;
    }
    if (validation_mode == GUARD_XPC_VALIDATION_DYNAMIC) {
        int requirementError = xpc_connection_set_peer_code_signing_requirement(
            server->listener, client_code_signing_requirement);
        if (requirementError != 0) {
            xpc_connection_cancel(server->listener);
            CFRelease(parsed);
            free(server);
            guard_copy_error(
                error_buffer, error_buffer_length,
                [NSString stringWithFormat:@"could not apply XPC client requirement: %s",
                                           strerror(requirementError)]);
            return NULL;
        }
    }
    xpc_connection_set_event_handler(server->listener, ^(xpc_object_t event) {
      GuardAcceptPeer(server, event);
    });
    return server;
}

void guard_xpc_server_activate(guard_xpc_server_t *server) {
    if (server == NULL) {
        return;
    }
    bool expected = false;
    if (atomic_compare_exchange_strong_explicit(
            &server->activated, &expected, true, memory_order_acq_rel,
            memory_order_acquire)) {
        xpc_connection_resume(server->listener);
    }
}

void guard_xpc_server_run(guard_xpc_server_t *server) {
    if (server != NULL) {
        guard_xpc_server_activate(server);
        [[NSRunLoop currentRunLoop] run];
    }
}

void guard_xpc_server_destroy(guard_xpc_server_t *server) {
    if (server == NULL) {
        return;
    }
    xpc_connection_cancel(server->listener);
    // A queued handler may still reference this process-lifetime service after
    // cancellation, so retain its small immutable context until process exit.
}

bool guard_xpc_request(const char *service_name,
                       const char *server_code_signing_requirement,
                       guard_xpc_validation_mode_t validation_mode,
                       const uint8_t *request,
                       size_t request_length,
                       uint64_t timeout_milliseconds,
                       uint8_t **response,
                       size_t *response_length,
                       char *error_buffer,
                       size_t error_buffer_length) {
    if (service_name == NULL || server_code_signing_requirement == NULL ||
        request == NULL || response == NULL || response_length == NULL ||
        timeout_milliseconds == 0 ||
        (validation_mode != GUARD_XPC_VALIDATION_DYNAMIC &&
         validation_mode != GUARD_XPC_VALIDATION_SELF_USE_STATIC)) {
        guard_copy_error(error_buffer, error_buffer_length,
                         @"invalid Guard XPC client request");
        return false;
    }

    SecRequirementRef parsed = GuardCreateRequirement(
        server_code_signing_requirement, error_buffer, error_buffer_length);
    if (parsed == NULL) {
        return false;
    }
    id parsedRequirement = CFBridgingRelease(parsed);
    dispatch_queue_t queue = dispatch_queue_create(
        "top.plfjy.guard.xpc.client", DISPATCH_QUEUE_SERIAL);
    xpc_connection_t connection =
        xpc_connection_create_mach_service(service_name, queue, 0);
    if (connection == NULL) {
        guard_copy_error(error_buffer, error_buffer_length,
                         @"could not create Guard XPC client connection");
        return false;
    }
    if (validation_mode == GUARD_XPC_VALIDATION_DYNAMIC) {
        int requirementError = xpc_connection_set_peer_code_signing_requirement(
            connection, server_code_signing_requirement);
        if (requirementError != 0) {
            xpc_connection_cancel(connection);
            guard_copy_error(
                error_buffer, error_buffer_length,
                [NSString stringWithFormat:@"could not apply XPC server requirement: %s",
                                           strerror(requirementError)]);
            return false;
        }
    }
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
      (void)event;
    });
    xpc_connection_resume(connection);

    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_data(message, GuardRequestKey, request, request_length);
    dispatch_semaphore_t completed = dispatch_semaphore_create(0);
    __block NSData *replyData = nil;
    __block NSString *replyError = nil;
    xpc_connection_send_message_with_reply(
        connection, message, queue, ^(xpc_object_t reply) {
          xpc_type_t replyType = xpc_get_type(reply);
          if (replyType != XPC_TYPE_DICTIONARY) {
              replyError = @"Guard XPC connection failed or was rejected";
              dispatch_semaphore_signal(completed);
              return;
          }
          if (validation_mode == GUARD_XPC_VALIDATION_SELF_USE_STATIC) {
              NSString *diagnostic = nil;
              if (!GuardValidateSelfUseMessage(
                      reply, (__bridge SecRequirementRef)parsedRequirement,
                      &diagnostic)) {
                  replyError = [NSString stringWithFormat:
                      @"XPC server authentication failed: %@",
                      diagnostic ?: @"signature validation failed"];
                  dispatch_semaphore_signal(completed);
                  return;
              }
          }
          const char *remoteError = xpc_dictionary_get_string(reply, GuardErrorKey);
          if (remoteError != NULL) {
              replyError = [NSString stringWithUTF8String:remoteError];
              dispatch_semaphore_signal(completed);
              return;
          }
          size_t length = 0;
          const void *bytes = xpc_dictionary_get_data(reply, GuardResponseKey, &length);
          if (bytes == NULL) {
              replyError = @"Guard XPC peer returned no response";
          } else {
              replyData = [NSData dataWithBytes:bytes length:length];
          }
          dispatch_semaphore_signal(completed);
        });

    uint64_t maximumMilliseconds = INT64_MAX / NSEC_PER_MSEC;
    int64_t timeoutNanoseconds =
        timeout_milliseconds > maximumMilliseconds
            ? INT64_MAX
            : (int64_t)(timeout_milliseconds * NSEC_PER_MSEC);
    dispatch_time_t deadline =
        dispatch_time(DISPATCH_TIME_NOW, timeoutNanoseconds);
    long waitResult = dispatch_semaphore_wait(completed, deadline);
    xpc_connection_cancel(connection);
    if (waitResult != 0) {
        guard_copy_error(error_buffer, error_buffer_length,
                         @"Guard XPC request timed out");
        return false;
    }
    if (replyData == nil) {
        guard_copy_error(error_buffer, error_buffer_length,
                         replyError ?: @"Guard XPC peer returned no response");
        return false;
    }
    uint8_t *bytes = malloc(replyData.length == 0 ? 1 : replyData.length);
    if (bytes == NULL) {
        guard_copy_error(error_buffer, error_buffer_length,
                         @"could not allocate XPC response");
        return false;
    }
    if (replyData.length != 0) {
        [replyData getBytes:bytes length:replyData.length];
    }
    *response = bytes;
    *response_length = replyData.length;
    return true;
}

void guard_xpc_bytes_free(uint8_t *bytes) { free(bytes); }

bool guard_code_signing_requirement_is_valid(const char *requirement,
                                             char *error_buffer,
                                             size_t error_buffer_length) {
    SecRequirementRef parsed = GuardCreateRequirement(
        requirement, error_buffer, error_buffer_length);
    if (parsed == NULL) {
        return false;
    }
    CFRelease(parsed);
    return true;
}
