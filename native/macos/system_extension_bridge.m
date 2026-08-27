#import "system_extension_bridge.h"

#import <Foundation/Foundation.h>
#import <Security/SecCode.h>
#import <Security/SecStaticCode.h>
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
        GuardRequestQueue = dispatch_queue_create("top.plfjy.guard.system-extension", DISPATCH_QUEUE_SERIAL);
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
    if (properties.count == 0) {
        GuardSetState(self.identifier, GuardLifecycleUnknown,
                      @"system extension is not installed");
    } else {
        BOOL hasAwaitingApproval = NO;
        BOOL hasInstalledDisabled = NO;
        BOOL hasUninstalling = NO;
        for (OSSystemExtensionProperties *property in properties) {
            // An update can briefly return both a retiring instance and the
            // replacement. Prefer the enabled replacement over stale teardown
            // state so diagnostics describe the effective protection state.
            if (property.isEnabled) {
                GuardSetState(self.identifier, GuardLifecycleActive,
                              @"system extension is enabled");
                @synchronized(GuardDelegates) {
                    [GuardDelegates removeObjectForKey:self.identifier];
                }
                return;
            }
            hasAwaitingApproval = hasAwaitingApproval || property.isAwaitingUserApproval;
            hasInstalledDisabled = hasInstalledDisabled || !property.isUninstalling;
            hasUninstalling = hasUninstalling || property.isUninstalling;
        }
        if (hasAwaitingApproval) {
        GuardSetState(self.identifier, GuardLifecycleUserApprovalRequired,
                      @"system extension is awaiting user approval");
        } else if (hasInstalledDisabled) {
            GuardSetState(self.identifier, GuardLifecycleDeactivated,
                          @"system extension is installed but disabled");
        } else if (hasUninstalling) {
            GuardSetState(self.identifier, GuardLifecycleDeactivated,
                          @"system extension is uninstalling");
        }
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

int guard_has_entitlement(const char *entitlement, char *error, size_t error_len) {
    if (entitlement == NULL) {
        GuardCopyCString(@"missing entitlement name", error, error_len);
        return -1;
    }
    NSString *entitlementName = [NSString stringWithUTF8String:entitlement];
    if (entitlementName.length == 0) {
        GuardCopyCString(@"invalid entitlement name", error, error_len);
        return -1;
    }
    SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    if (task == NULL) {
        GuardCopyCString(@"SecTaskCreateFromSelf returned NULL", error, error_len);
        return -1;
    }
    CFErrorRef entitlementError = NULL;
    CFTypeRef value = SecTaskCopyValueForEntitlement(
        task, (__bridge CFStringRef)entitlementName, &entitlementError);
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

static void GuardCopyOSStatus(OSStatus status, char *error, size_t error_len) {
    CFStringRef message = SecCopyErrorMessageString(status, NULL);
    if (message == NULL) {
        GuardCopyCString([NSString stringWithFormat:@"Security.framework error %d", (int)status],
                         error, error_len);
        return;
    }
    GuardCopyCString((__bridge NSString *)message, error, error_len);
    CFRelease(message);
}

int guard_path_has_entitlement(const char *path, const char *entitlement,
                               char *error, size_t error_len) {
    if (path == NULL || entitlement == NULL) {
        GuardCopyCString(@"missing code path or entitlement name", error, error_len);
        return -1;
    }
    NSString *codePath = [NSString stringWithUTF8String:path];
    NSString *entitlementName = [NSString stringWithUTF8String:entitlement];
    if (codePath.length == 0 || entitlementName.length == 0) {
        GuardCopyCString(@"invalid code path or entitlement name", error, error_len);
        return -1;
    }

    SecStaticCodeRef code = NULL;
    NSURL *codeURL = [NSURL fileURLWithPath:codePath];
    OSStatus status = SecStaticCodeCreateWithPath(
        (__bridge CFURLRef)codeURL, kSecCSDefaultFlags, &code);
    if (status != errSecSuccess) {
        GuardCopyOSStatus(status, error, error_len);
        return -1;
    }
    status = SecStaticCodeCheckValidity(code, kSecCSStrictValidate, NULL);
    if (status != errSecSuccess) {
        CFRelease(code);
        GuardCopyOSStatus(status, error, error_len);
        return -1;
    }

    CFDictionaryRef information = NULL;
    status = SecCodeCopySigningInformation(
        code, kSecCSSigningInformation, &information);
    CFRelease(code);
    if (status != errSecSuccess) {
        GuardCopyOSStatus(status, error, error_len);
        return -1;
    }
    CFTypeRef entitlementObject = CFDictionaryGetValue(
        information, kSecCodeInfoEntitlementsDict);
    CFDictionaryRef entitlements = entitlementObject != NULL
        && CFGetTypeID(entitlementObject) == CFDictionaryGetTypeID()
        ? (CFDictionaryRef)entitlementObject : NULL;
    CFTypeRef value = entitlements == NULL ? NULL : CFDictionaryGetValue(
        entitlements, (__bridge CFStringRef)entitlementName);
    BOOL present = value != NULL && CFGetTypeID(value) == CFBooleanGetTypeID()
                   && CFBooleanGetValue((CFBooleanRef)value);
    CFRelease(information);
    return present ? 1 : 0;
}
