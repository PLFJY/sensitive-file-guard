#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>

@protocol GuardXPCProbeProtocol
- (void)request:(NSData *)request
      withReply:(void (^)(NSData *_Nullable response,
                          NSString *_Nullable error))reply;
@end

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 2) {
            fprintf(stderr, "usage: xpc-wrong-signed-probe SERVICE_NAME\n");
            return 2;
        }
        NSString *service = [NSString stringWithUTF8String:argv[1]];
        NSXPCConnection *connection =
            [[NSXPCConnection alloc] initWithMachServiceName:service options:0];
        connection.remoteObjectInterface =
            [NSXPCInterface interfaceWithProtocol:@protocol(GuardXPCProbeProtocol)];
        [connection activate];

        dispatch_semaphore_t finished = dispatch_semaphore_create(0);
        __block BOOL receivedResponse = NO;
        id<GuardXPCProbeProtocol> proxy =
            [connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
              (void)error;
              dispatch_semaphore_signal(finished);
            }];
        // Attempt the capability-expanding operation directly, without the
        // signed client or LocalAuthentication. The XPC signing requirement
        // must reject this connection before the handler can reply, whether
        // or not the synthetic pending ID exists.
        NSData *request = [@"{\"version\":5,\"op\":{\"kind\":\"ssh_read_resolve\",\"id\":\"synthetic-pending\",\"action\":\"allow\"}}"
            dataUsingEncoding:NSUTF8StringEncoding];
        [proxy request:request
              withReply:^(NSData *response, NSString *error) {
                (void)error;
                receivedResponse = response != nil;
                dispatch_semaphore_signal(finished);
              }];
        dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC);
        (void)dispatch_semaphore_wait(finished, deadline);
        [connection invalidate];
        if (receivedResponse) {
            fprintf(stderr,
                    "FAIL: wrong-signed same-UID process reached SSH Allow XPC\n");
            return 1;
        }
        fprintf(stderr,
                "PASS: wrong-signed same-UID SSH Allow attempt was rejected\n");
        return 0;
    }
}
