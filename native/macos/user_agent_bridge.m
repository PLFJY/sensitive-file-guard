#import "user_agent_bridge.h"

#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>

static void GuardCopyAgentError(char *buffer, size_t length, NSString *message) {
    if (buffer == NULL || length == 0) {
        return;
    }
    strlcpy(buffer, message.UTF8String ?: "SMAppService failed", length);
}

static SMAppService *GuardAgentService(const char *plistName,
                                       char *errorBuffer,
                                       size_t errorBufferLength) {
    if (plistName == NULL) {
        GuardCopyAgentError(errorBuffer, errorBufferLength,
                            @"missing LaunchAgent plist name");
        return nil;
    }
    NSString *name = [NSString stringWithUTF8String:plistName];
    if (name.length == 0 || ![name hasSuffix:@".plist"] ||
        [name containsString:@"/"]) {
        GuardCopyAgentError(errorBuffer, errorBufferLength,
                            @"invalid embedded LaunchAgent plist name");
        return nil;
    }
    return [SMAppService agentServiceWithPlistName:name];
}

int guard_user_agent_status(const char *plist_name,
                            char *error_buffer,
                            size_t error_buffer_length) {
    SMAppService *service = GuardAgentService(plist_name, error_buffer,
                                              error_buffer_length);
    if (service == nil) {
        return -1;
    }
    switch (service.status) {
    case SMAppServiceStatusNotRegistered:
        return 0;
    case SMAppServiceStatusEnabled:
        return 1;
    case SMAppServiceStatusRequiresApproval:
        return 2;
    case SMAppServiceStatusNotFound:
        return 3;
    }
    GuardCopyAgentError(error_buffer, error_buffer_length,
                        @"SMAppService returned an unknown status");
    return -1;
}

int guard_user_agent_register(const char *plist_name,
                              char *error_buffer,
                              size_t error_buffer_length) {
    SMAppService *service = GuardAgentService(plist_name, error_buffer,
                                              error_buffer_length);
    if (service == nil) {
        return -1;
    }
    if (service.status == SMAppServiceStatusEnabled ||
        service.status == SMAppServiceStatusRequiresApproval) {
        return 0;
    }
    NSError *error = nil;
    if (![service registerAndReturnError:&error]) {
        GuardCopyAgentError(error_buffer, error_buffer_length,
                            error.localizedDescription);
        return -1;
    }
    return 0;
}

int guard_user_agent_unregister(const char *plist_name,
                                char *error_buffer,
                                size_t error_buffer_length) {
    SMAppService *service = GuardAgentService(plist_name, error_buffer,
                                              error_buffer_length);
    if (service == nil) {
        return -1;
    }
    if (service.status == SMAppServiceStatusNotRegistered ||
        service.status == SMAppServiceStatusNotFound) {
        return 0;
    }
    NSError *error = nil;
    if (![service unregisterAndReturnError:&error]) {
        GuardCopyAgentError(error_buffer, error_buffer_length,
                            error.localizedDescription);
        return -1;
    }
    return 0;
}

void guard_user_agent_open_settings(void) {
    [SMAppService openSystemSettingsLoginItems];
}
