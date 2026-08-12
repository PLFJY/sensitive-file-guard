#import "notification_bridge.h"

#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

static void GuardCopyNotificationError(char *buffer,
                                       size_t length,
                                       NSString *message) {
    if (buffer == NULL || length == 0) {
        return;
    }
    strlcpy(buffer, message.UTF8String ?: "macOS notification failed", length);
}

int guard_user_notification(const char *title,
                            const char *body,
                            char *error_buffer,
                            size_t error_buffer_length) {
    if (title == NULL || body == NULL) {
        GuardCopyNotificationError(error_buffer, error_buffer_length,
                                   @"notification title/body is missing");
        return -1;
    }
    NSString *titleString = [NSString stringWithUTF8String:title];
    NSString *bodyString = [NSString stringWithUTF8String:body];
    if (titleString == nil || bodyString == nil || titleString.length == 0 ||
        bodyString.length == 0) {
        GuardCopyNotificationError(error_buffer, error_buffer_length,
                                   @"notification title/body is invalid UTF-8");
        return -1;
    }

    NSUserNotificationCenter *center = [NSUserNotificationCenter defaultUserNotificationCenter];
    if (center == nil) {
        GuardCopyNotificationError(error_buffer, error_buffer_length,
                                   @"NSUserNotificationCenter is unavailable");
        return -1;
    }
    NSUserNotification *notification = [NSUserNotification new];
    notification.title = titleString;
    notification.informativeText = bodyString;
    notification.soundName = NSUserNotificationDefaultSoundName;
    [center deliverNotification:notification];
    return 0;
}

#pragma clang diagnostic pop
