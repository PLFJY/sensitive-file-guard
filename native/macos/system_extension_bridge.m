#import "system_extension_bridge.h"

#import <Foundation/Foundation.h>
#import <Security/SecTask.h>
#import <SystemExtensions/SystemExtensions.h>

typedef NS_ENUM(NSInteger, GuardLifecycleState) {
    GuardLifecycleUnknown = 0,
    GuardLifecycleSubmitted = 1,
    GuardLifecycleUserApprovalRequired = 2,
    GuardLifecycleActive = 3,
    GuardLifecycleRestartRequired = 4,
    GuardLifecycleDeactivated = 5,
    GuardLifecycleFailed = 6,
};

static NSMutableDictionary<NSString *, NSNumber *> *GuardStates;
static NSMutableDictionary<NSString *, NSString *> *GuardDiagnostics;
static NSMutableDictionary<NSString *, id> *GuardDelegates;
static dispatch_queue_t GuardRequestQueue;

static void GuardInitialize(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        GuardStates = [NSMutableDictionary dictionary];
        GuardDiagnostics = [NSMutableDictionary dictionary];
        GuardDelegates = [NSMutableDictionary dictionary];
        GuardRequestQueue = dispatch_queue_create("io.github.plfjy.guard.system-extension", DISPATCH_QUEUE_SERIAL);
    });
}

static void GuardSetState(NSString *identifier, GuardLifecycleState state, NSString *diagnostic) {
    GuardInitialize();
    @synchronized(GuardStates) {
        GuardStates[identifier] = @(state);
        GuardDiagnostics[identifier] = diagnostic ?: @"";
    }
}

static void GuardCopyCString(NSString *value, char *buffer, size_t length) {
    if (buffer == NULL || length == 0) {
        return;
    }
    const char *utf8 = value.UTF8String ?: "";
    strlcpy(buffer, utf8, length);
}

static NSString *GuardIdentifier(const char *identifier, char *error, size_t errorLength) {
    if (identifier == NULL) {
        GuardCopyCString(@"missing system extension bundle identifier", error, errorLength);
        return nil;
    }
    NSString *value = [NSString stringWithUTF8String:identifier];
    if (value.length == 0) {
        GuardCopyCString(@"invalid UTF-8 system extension bundle identifier", error, errorLength);
        return nil;
    }
    return value;
}

@interface GuardSystemExtensionDelegate : NSObject <OSSystemExtensionRequestDelegate>
@property(nonatomic, copy) NSString *identifier;
@property(nonatomic) BOOL activating;
@end

@implementation GuardSystemExtensionDelegate
- (OSSystemExtensionReplacementAction)request:(OSSystemExtensionRequest *)request
                 actionForReplacingExtension:(OSSystemExtensionProperties *)existing
                               withExtension:(OSSystemExtensionProperties *)extension {
    (void)request;
    (void)existing;
    (void)extension;
    return OSSystemExtensionReplacementActionReplace;
}

- (void)requestNeedsUserApproval:(OSSystemExtensionRequest *)request {
    (void)request;
    GuardSetState(self.identifier, GuardLifecycleUserApprovalRequired,
                  @"system extension activation is awaiting user approval");
}

- (void)request:(OSSystemExtensionRequest *)request
    didFinishWithResult:(OSSystemExtensionRequestResult)result {
    (void)request;
    if (result == OSSystemExtensionRequestWillCompleteAfterReboot) {
        GuardSetState(self.identifier, GuardLifecycleRestartRequired,
                      @"system extension request completed; restart required");
    } else if (self.activating) {
        GuardSetState(self.identifier, GuardLifecycleActive,
                      @"system extension activation completed");
    } else {
        GuardSetState(self.identifier, GuardLifecycleDeactivated,
                      @"system extension deactivation completed");
    }
    @synchronized(GuardDelegates) {
        [GuardDelegates removeObjectForKey:self.identifier];
    }
}

- (void)request:(OSSystemExtensionRequest *)request didFailWithError:(NSError *)error {
    (void)request;
    GuardSetState(self.identifier, GuardLifecycleFailed, error.localizedDescription);
    @synchronized(GuardDelegates) {
        [GuardDelegates removeObjectForKey:self.identifier];
    }
}

- (void)request:(OSSystemExtensionRequest *)request
    foundProperties:(NSArray<OSSystemExtensionProperties *> *)properties API_AVAILABLE(macos(12.0)) {
    (void)request;
    OSSystemExtensionProperties *property = properties.firstObject;
    if (property == nil) {
        GuardSetState(self.identifier, GuardLifecycleUnknown,
                      @"system extension is not installed");
    } else if (property.isUninstalling) {
        GuardSetState(self.identifier, GuardLifecycleDeactivated,
                      @"system extension is uninstalling");
    } else if (property.isAwaitingUserApproval) {
        GuardSetState(self.identifier, GuardLifecycleUserApprovalRequired,
                      @"system extension is awaiting user approval");
    } else if (property.isEnabled) {
        GuardSetState(self.identifier, GuardLifecycleActive,
                      @"system extension is enabled");
    } else {
        GuardSetState(self.identifier, GuardLifecycleDeactivated,
                      @"system extension is installed but disabled");
    }
    @synchronized(GuardDelegates) {
        [GuardDelegates removeObjectForKey:self.identifier];
    }
}
@end

static int GuardSubmit(const char *identifier, BOOL activating, BOOL properties,
                       char *error, size_t errorLength) {
    NSString *bundleIdentifier = GuardIdentifier(identifier, error, errorLength);
    if (bundleIdentifier == nil) {
        return -1;
    }
    GuardInitialize();
    GuardSetState(bundleIdentifier, GuardLifecycleSubmitted,
                  properties ? @"system extension status query submitted"
                             : @"system extension lifecycle request submitted");
    dispatch_async(GuardRequestQueue, ^{
        GuardSystemExtensionDelegate *delegate = [GuardSystemExtensionDelegate new];
        delegate.identifier = bundleIdentifier;
        delegate.activating = activating;
        OSSystemExtensionRequest *request;
        if (properties) {
            if (@available(macOS 12.0, *)) {
                request = [OSSystemExtensionRequest propertiesRequestForExtension:bundleIdentifier
                                                                              queue:GuardRequestQueue];
            } else {
                GuardSetState(bundleIdentifier, GuardLifecycleFailed,
                              @"system extension status queries require macOS 12 or newer");
                return;
            }
        } else if (activating) {
            request = [OSSystemExtensionRequest activationRequestForExtension:bundleIdentifier
                                                                          queue:GuardRequestQueue];
        } else {
            request = [OSSystemExtensionRequest deactivationRequestForExtension:bundleIdentifier
                                                                            queue:GuardRequestQueue];
        }
        request.delegate = delegate;
        @synchronized(GuardDelegates) {
            GuardDelegates[bundleIdentifier] = delegate;
        }
        [OSSystemExtensionManager.sharedManager submitRequest:request];
    });
    return 0;
}

int guard_system_extension_activate(const char *identifier, char *error, size_t error_len) {
    return GuardSubmit(identifier, YES, NO, error, error_len);
}

int guard_system_extension_deactivate(const char *identifier, char *error, size_t error_len) {
    return GuardSubmit(identifier, NO, NO, error, error_len);
}

int guard_system_extension_refresh(const char *identifier, char *error, size_t error_len) {
    return GuardSubmit(identifier, NO, YES, error, error_len);
}

int guard_system_extension_status(const char *identifier, char *diagnostic, size_t diagnostic_len) {
    NSString *bundleIdentifier = GuardIdentifier(identifier, diagnostic, diagnostic_len);
    if (bundleIdentifier == nil) {
        return GuardLifecycleFailed;
    }
    GuardInitialize();
    @synchronized(GuardStates) {
        NSNumber *state = GuardStates[bundleIdentifier];
        NSString *message = GuardDiagnostics[bundleIdentifier] ?: @"no lifecycle request submitted";
        GuardCopyCString(message, diagnostic, diagnostic_len);
        return state == nil ? GuardLifecycleUnknown : state.intValue;
    }
}

int guard_has_endpoint_security_entitlement(char *error, size_t error_len) {
    SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    if (task == NULL) {
        GuardCopyCString(@"SecTaskCreateFromSelf returned NULL", error, error_len);
        return -1;
    }
    CFErrorRef entitlementError = NULL;
    CFTypeRef value = SecTaskCopyValueForEntitlement(
        task, CFSTR("com.apple.developer.endpoint-security.client"), &entitlementError);
    CFRelease(task);
    if (entitlementError != NULL) {
        NSString *message = CFBridgingRelease(CFErrorCopyDescription(entitlementError));
        CFRelease(entitlementError);
        GuardCopyCString(message, error, error_len);
        if (value != NULL) {
            CFRelease(value);
        }
        return -1;
    }
    BOOL present = value != NULL && CFGetTypeID(value) == CFBooleanGetTypeID()
                   && CFBooleanGetValue((CFBooleanRef)value);
    if (value != NULL) {
        CFRelease(value);
    }
    return present ? 1 : 0;
}
