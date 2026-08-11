#import "code_signature_bridge.h"

#import <Foundation/Foundation.h>
#import <Security/SecCode.h>
#import <Security/SecStaticCode.h>

#include <string.h>

static void GuardSignatureCopyString(CFStringRef value, char *buffer, size_t length) {
    if (buffer == NULL || length == 0) {
        return;
    }
    buffer[0] = '\0';
    if (value != NULL) {
        CFStringGetCString(value, buffer, length, kCFStringEncodingUTF8);
    }
}

static void GuardSignatureError(OSStatus status, char *error, size_t errorLength) {
    CFStringRef message = SecCopyErrorMessageString(status, NULL);
    GuardSignatureCopyString(message, error, errorLength);
    if (message != NULL) {
        CFRelease(message);
    }
}

int guard_code_signature_inspect(
    const char *path,
    guard_code_signature_info_t *info,
    char *error,
    size_t error_len) {
    if (path == NULL || info == NULL) {
        GuardSignatureCopyString(CFSTR("missing code-signature path or output"), error, error_len);
        return -1;
    }
    memset(info, 0, sizeof(*info));
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        kCFAllocatorDefault, (const UInt8 *)path, strlen(path), false);
    if (url == NULL) {
        GuardSignatureCopyString(CFSTR("invalid executable path"), error, error_len);
        return -1;
    }
    SecStaticCodeRef code = NULL;
    OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    CFRelease(url);
    if (status != errSecSuccess) {
        GuardSignatureError(status, error, error_len);
        return -1;
    }
    status = SecStaticCodeCheckValidity(
        code, kSecCSStrictValidate | kSecCSCheckAllArchitectures, NULL);
    info->valid = status == errSecSuccess;

    CFDictionaryRef signingInformation = NULL;
    OSStatus informationStatus = SecCodeCopySigningInformation(
        code, kSecCSSigningInformation, &signingInformation);
    CFRelease(code);
    if (informationStatus != errSecSuccess) {
        GuardSignatureError(informationStatus, error, error_len);
        return -1;
    }
    CFStringRef team = CFDictionaryGetValue(signingInformation, kSecCodeInfoTeamIdentifier);
    CFStringRef signing = CFDictionaryGetValue(signingInformation, kSecCodeInfoIdentifier);
    CFDataRef cdhash = CFDictionaryGetValue(signingInformation, kSecCodeInfoUnique);
    GuardSignatureCopyString(team, info->team_id, sizeof(info->team_id));
    GuardSignatureCopyString(signing, info->signing_id, sizeof(info->signing_id));
    if (cdhash != NULL) {
        CFIndex length = CFDataGetLength(cdhash);
        if (length > 0 && length <= (CFIndex)sizeof(info->cdhash)) {
            CFDataGetBytes(cdhash, CFRangeMake(0, length), info->cdhash);
            info->cdhash_len = (size_t)length;
        }
    }
    CFRelease(signingInformation);
    if (!info->valid) {
        GuardSignatureError(status, error, error_len);
    }
    return 0;
}
