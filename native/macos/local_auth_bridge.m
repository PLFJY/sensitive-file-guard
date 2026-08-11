#import "local_auth_bridge.h"

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <dispatch/dispatch.h>

static void guard_copy_auth_error(char *buffer, size_t length, NSString *message) {
    if (buffer == NULL || length == 0) {
        return;
    }
    const char *utf8 = message.UTF8String;
    snprintf(buffer, length, "%s", utf8 ?: "LocalAuthentication failed");
}

guard_local_auth_result_t guard_local_authenticate(
    const char *localized_reason,
    uint64_t timeout_milliseconds,
    char *error_buffer,
    size_t error_buffer_length) {
    if (localized_reason == NULL || timeout_milliseconds == 0) {
        guard_copy_auth_error(error_buffer, error_buffer_length,
                              @"invalid LocalAuthentication request");
        return GUARD_LOCAL_AUTH_FAILED;
    }
    NSString *reason = [NSString stringWithUTF8String:localized_reason];
    if (reason == nil || reason.length == 0) {
        guard_copy_auth_error(error_buffer, error_buffer_length,
                              @"authentication reason must be non-empty UTF-8");
        return GUARD_LOCAL_AUTH_FAILED;
    }

    LAContext *context = [LAContext new];
    context.localizedCancelTitle = @"Cancel";
    NSError *availabilityError = nil;
    if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication
                              error:&availabilityError]) {
        guard_copy_auth_error(error_buffer, error_buffer_length,
                              availabilityError.localizedDescription);
        return GUARD_LOCAL_AUTH_UNAVAILABLE;
    }

    dispatch_semaphore_t completed = dispatch_semaphore_create(0);
    __block BOOL succeeded = NO;
    __block NSError *evaluationError = nil;
    [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
            localizedReason:reason
                      reply:^(BOOL success, NSError *error) {
                        succeeded = success;
                        evaluationError = error;
                        dispatch_semaphore_signal(completed);
                      }];

    uint64_t maximumMilliseconds = INT64_MAX / NSEC_PER_MSEC;
    int64_t timeoutNanoseconds =
        timeout_milliseconds > maximumMilliseconds
            ? INT64_MAX
            : (int64_t)(timeout_milliseconds * NSEC_PER_MSEC);
    dispatch_time_t deadline =
        dispatch_time(DISPATCH_TIME_NOW, timeoutNanoseconds);
    if (dispatch_semaphore_wait(completed, deadline) != 0) {
        [context invalidate];
        guard_copy_auth_error(error_buffer, error_buffer_length,
                              @"device-owner authentication timed out");
        return GUARD_LOCAL_AUTH_TIMED_OUT;
    }
    if (succeeded) {
        return GUARD_LOCAL_AUTH_SUCCESS;
    }
    guard_copy_auth_error(error_buffer, error_buffer_length,
                          evaluationError.localizedDescription);
    switch (evaluationError.code) {
    case LAErrorUserCancel:
    case LAErrorAppCancel:
    case LAErrorSystemCancel:
        return GUARD_LOCAL_AUTH_CANCELLED;
    default:
        return GUARD_LOCAL_AUTH_FAILED;
    }
}
