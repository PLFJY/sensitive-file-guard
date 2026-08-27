#import "xpc_bridge.h"

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dispatch/dispatch.h>
#import <stdatomic.h>

@protocol GuardXPCProtocol
- (void)request:(NSData *)request
      withReply:(void (^)(NSData *_Nullable response,
                          NSString *_Nullable error))reply;
@end

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

@interface GuardXPCExportedObject : NSObject <GuardXPCProtocol>
@property(nonatomic, assign) uint32_t peerEuid;
@property(nonatomic, assign) size_t maximumRequestBytes;
@property(nonatomic, assign) size_t maximumConcurrentRequests;
@property(nonatomic, assign) guard_xpc_request_callback_t callback;
@property(nonatomic, assign) guard_xpc_response_free_t responseFree;
@property(nonatomic, assign) void *context;
@property(nonatomic, assign) _Atomic size_t *activeRequests;
@end

@implementation GuardXPCExportedObject
- (void)request:(NSData *)request
      withReply:(void (^)(NSData *_Nullable, NSString *_Nullable))reply {
    if (request.length > self.maximumRequestBytes) {
        reply(nil, @"request exceeds guard-ipc MAX_REQUEST_BYTES");
        return;
    }
    size_t previous = atomic_fetch_add_explicit(self.activeRequests, 1,
                                                memory_order_acq_rel);
    if (previous >= self.maximumConcurrentRequests) {
        atomic_fetch_sub_explicit(self.activeRequests, 1, memory_order_acq_rel);
        reply(nil, @"XPC request concurrency limit reached");
        return;
    }

    const uint8_t *responseBytes = NULL;
    size_t responseLength = 0;
    bool handled = self.callback(request.bytes, request.length, self.peerEuid,
                                 &responseBytes, &responseLength, self.context);
    NSData *response = nil;
    if (handled && responseBytes != NULL) {
        response = [NSData dataWithBytes:responseBytes length:responseLength];
        self.responseFree(responseBytes, responseLength, self.context);
    }
    atomic_fetch_sub_explicit(self.activeRequests, 1, memory_order_acq_rel);
    if (!handled || response == nil) {
        reply(nil, @"Guard XPC request handler failed closed");
        return;
    }
    reply(response, nil);
}
@end

@interface GuardXPCListenerDelegate : NSObject <NSXPCListenerDelegate>
@property(nonatomic, copy) NSString *clientRequirement;
@property(nonatomic, assign) size_t maximumRequestBytes;
@property(nonatomic, assign) size_t maximumConcurrentRequests;
@property(nonatomic, assign) guard_xpc_peer_callback_t peerCallback;
@property(nonatomic, assign) guard_xpc_request_callback_t requestCallback;
@property(nonatomic, assign) guard_xpc_response_free_t responseFree;
@property(nonatomic, assign) void *context;
@property(nonatomic, assign) _Atomic size_t *activeRequests;
@property(nonatomic, strong) NSMutableSet<GuardXPCExportedObject *> *exportedObjects;
@end

@implementation GuardXPCListenerDelegate
- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _exportedObjects = [NSMutableSet set];
    }
    return self;
}

- (BOOL)listener:(NSXPCListener *)listener
    shouldAcceptNewConnection:(NSXPCConnection *)connection {
    (void)listener;
    uint32_t euid = connection.effectiveUserIdentifier;
    if (!self.peerCallback(euid, self.context)) {
        return NO;
    }

    @try {
        // On serviceListener the listener-wide convenience API is unavailable.
        // Applying the exact requirement to each connection before activation
        // makes Foundation invalidate a peer before any exported method runs.
        [connection setCodeSigningRequirement:self.clientRequirement];
    } @catch (NSException *exception) {
        return NO;
    }

    GuardXPCExportedObject *exported = [GuardXPCExportedObject new];
    exported.peerEuid = euid;
    exported.maximumRequestBytes = self.maximumRequestBytes;
    exported.maximumConcurrentRequests = self.maximumConcurrentRequests;
    exported.callback = self.requestCallback;
    exported.responseFree = self.responseFree;
    exported.context = self.context;
    exported.activeRequests = self.activeRequests;
    connection.exportedInterface =
        [NSXPCInterface interfaceWithProtocol:@protocol(GuardXPCProtocol)];
    connection.exportedObject = exported;

    __weak GuardXPCListenerDelegate *weakSelf = self;
    __weak GuardXPCExportedObject *weakExported = exported;
    connection.invalidationHandler = ^{
      GuardXPCListenerDelegate *strongSelf = weakSelf;
      GuardXPCExportedObject *strongExported = weakExported;
      if (strongSelf != nil && strongExported != nil) {
          @synchronized(strongSelf.exportedObjects) {
              [strongSelf.exportedObjects removeObject:strongExported];
          }
      }
    };
    @synchronized(self.exportedObjects) {
        [self.exportedObjects addObject:exported];
    }
    [connection activate];
    return YES;
}
@end

struct guard_xpc_server {
    NSXPCListener *listener;
    GuardXPCListenerDelegate *delegate;
    _Atomic size_t active_requests;
};

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
    size_t error_buffer_length) {
    if (service_name == NULL || client_code_signing_requirement == NULL ||
        maximum_request_bytes == 0 ||
        maximum_concurrent_requests == 0 || peer_callback == NULL ||
        request_callback == NULL || response_free == NULL) {
        guard_copy_error(error_buffer, error_buffer_length,
                         @"invalid Guard XPC server configuration");
        return NULL;
    }
    NSString *requirement =
        [NSString stringWithUTF8String:client_code_signing_requirement];
    NSString *service = [NSString stringWithUTF8String:service_name];
    if (requirement == nil || service == nil) {
        guard_copy_error(error_buffer, error_buffer_length,
                         @"service name or client requirement is not UTF-8");
        return NULL;
    }

    guard_xpc_server_t *server = calloc(1, sizeof(*server));
    if (server == NULL) {
        guard_copy_error(error_buffer, error_buffer_length,
                         @"could not allocate Guard XPC server");
        return NULL;
    }
    atomic_init(&server->active_requests, 0);
    // NSEndpointSecurityMachServiceName is a named system-extension Mach
    // service. Foundation binds this listener to that declared service; it is
    // not an embedded XPC-service bundle and must not use serviceListener.
    server->listener = [[NSXPCListener alloc] initWithMachServiceName:service];
    server->delegate = [GuardXPCListenerDelegate new];
    server->delegate.clientRequirement = requirement;
    server->delegate.maximumRequestBytes = maximum_request_bytes;
    server->delegate.maximumConcurrentRequests = maximum_concurrent_requests;
    server->delegate.peerCallback = peer_callback;
    server->delegate.requestCallback = request_callback;
    server->delegate.responseFree = response_free;
    server->delegate.context = context;
    server->delegate.activeRequests = &server->active_requests;
    server->listener.delegate = server->delegate;
    return server;
}

void guard_xpc_server_activate(guard_xpc_server_t *server) {
    if (server != NULL) {
        [server->listener activate];
    }
}

void guard_xpc_server_run(guard_xpc_server_t *server) {
    if (server != NULL) {
        [server->listener activate];
        [[NSRunLoop currentRunLoop] run];
    }
}

void guard_xpc_server_destroy(guard_xpc_server_t *server) {
    if (server == NULL) {
        return;
    }
    [server->listener invalidate];
    server->listener.delegate = nil;
    server->delegate = nil;
    server->listener = nil;
    // An invalidated connection may still finish an already-delivered method
    // and touch active_requests. Keep this tiny callback state until process
    // exit, matching the Rust handler-context lifetime, rather than risk UAF.
}

bool guard_xpc_request(const char *service_name,
                       const char *server_code_signing_requirement,
                       const uint8_t *request,
                       size_t request_length,
                       uint64_t timeout_milliseconds,
                       uint8_t **response,
                       size_t *response_length,
                       char *error_buffer,
                       size_t error_buffer_length) {
    if (service_name == NULL || server_code_signing_requirement == NULL ||
        request == NULL || response == NULL || response_length == NULL ||
        timeout_milliseconds == 0) {
        guard_copy_error(error_buffer, error_buffer_length,
                         @"invalid Guard XPC client request");
        return false;
    }
    NSString *service = [NSString stringWithUTF8String:service_name];
    NSString *requirement =
        [NSString stringWithUTF8String:server_code_signing_requirement];
    if (service == nil || requirement == nil) {
        guard_copy_error(error_buffer, error_buffer_length,
                         @"XPC service or requirement is not UTF-8");
        return false;
    }

    NSXPCConnection *connection =
        [[NSXPCConnection alloc] initWithMachServiceName:service options:0];
    connection.remoteObjectInterface =
        [NSXPCInterface interfaceWithProtocol:@protocol(GuardXPCProtocol)];
    @try {
        [connection setCodeSigningRequirement:requirement];
    } @catch (NSException *exception) {
        guard_copy_error(error_buffer, error_buffer_length, exception.reason);
        return false;
    }
    [connection activate];

    dispatch_semaphore_t completed = dispatch_semaphore_create(0);
    __block NSData *replyData = nil;
    __block NSString *replyError = nil;
    id<GuardXPCProtocol> proxy =
        [connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
          replyError = error.localizedDescription;
          dispatch_semaphore_signal(completed);
        }];
    NSData *payload = [NSData dataWithBytes:request length:request_length];
    [proxy request:payload
          withReply:^(NSData *data, NSString *error) {
            replyData = data;
            replyError = error;
            dispatch_semaphore_signal(completed);
          }];

    uint64_t maximumMilliseconds = INT64_MAX / NSEC_PER_MSEC;
    int64_t timeoutNanoseconds =
        timeout_milliseconds > maximumMilliseconds
            ? INT64_MAX
            : (int64_t)(timeout_milliseconds * NSEC_PER_MSEC);
    dispatch_time_t deadline =
        dispatch_time(DISPATCH_TIME_NOW, timeoutNanoseconds);
    long waitResult = dispatch_semaphore_wait(completed, deadline);
    [connection invalidate];
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
    if (requirement == NULL) {
        guard_copy_error(error_buffer, error_buffer_length,
                         @"code-signing requirement is missing");
        return false;
    }
    NSString *text = [NSString stringWithUTF8String:requirement];
    if (text == nil) {
        guard_copy_error(error_buffer, error_buffer_length,
                         @"code-signing requirement is not UTF-8");
        return false;
    }
    SecRequirementRef parsed = NULL;
    OSStatus status = SecRequirementCreateWithString(
        (__bridge CFStringRef)text, kSecCSDefaultFlags, &parsed);
    if (parsed != NULL) {
        CFRelease(parsed);
    }
    if (status != errSecSuccess) {
        NSString *message = CFBridgingRelease(SecCopyErrorMessageString(status, NULL));
        guard_copy_error(error_buffer, error_buffer_length,
                         message ?: @"invalid code-signing requirement");
        return false;
    }
    return true;
}
