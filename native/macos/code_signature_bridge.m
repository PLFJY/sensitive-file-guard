#import "code_signature_bridge.h"

#import <Foundation/Foundation.h>
#import <Security/SecCode.h>
#import <Security/SecStaticCode.h>

#import <CommonCrypto/CommonDigest.h>

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

static void GuardSignatureCopyCertificateSha1(SecCertificateRef certificate,
                                              char *buffer, size_t length) {
    if (certificate == NULL || buffer == NULL || length < CC_SHA1_DIGEST_LENGTH * 2 + 1) {
        return;
    }
    CFDataRef data = SecCertificateCopyData(certificate);
    if (data == NULL) {
        return;
    }
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(CFDataGetBytePtr(data), (CC_LONG)CFDataGetLength(data), digest);
    CFRelease(data);
    for (size_t index = 0; index < sizeof(digest); index++) {
        snprintf(buffer + index * 2, length - index * 2, "%02X", digest[index]);
    }
}

int guard_code_signature_runtime_inspect(
    const char *path,
    guard_code_signature_runtime_info_t *info,
    char *error,
    size_t error_len) {
    if (path == NULL || info == NULL) {
        GuardSignatureCopyString(CFSTR("missing runtime-signature path or output"), error, error_len);
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
    CFDictionaryRef signingInformation = NULL;
    OSStatus informationStatus = SecCodeCopySigningInformation(
        code, kSecCSSigningInformation, &signingInformation);
    CFRelease(code);
    if (informationStatus != errSecSuccess) {
        GuardSignatureError(informationStatus, error, error_len);
        return -1;
    }
    CFDictionaryRef entitlements = CFDictionaryGetValue(
        signingInformation, kSecCodeInfoEntitlementsDict);
    if (entitlements != NULL) {
        info->has_entitlements = true;
        info->get_task_allow = CFDictionaryGetValue(entitlements,
            CFSTR("com.apple.security.get-task-allow")) != NULL;
        info->allow_dyld_environment_variables = CFDictionaryGetValue(entitlements,
            CFSTR("com.apple.security.cs.allow-dyld-environment-variables")) != NULL;
        info->disable_library_validation = CFDictionaryGetValue(entitlements,
            CFSTR("com.apple.security.cs.disable-library-validation")) != NULL;
        info->disable_executable_page_protection = CFDictionaryGetValue(entitlements,
            CFSTR("com.apple.security.cs.disable-executable-page-protection")) != NULL;
        info->allow_unsigned_executable_memory = CFDictionaryGetValue(entitlements,
            CFSTR("com.apple.security.cs.allow-unsigned-executable-memory")) != NULL;
        info->allow_jit = CFDictionaryGetValue(entitlements,
            CFSTR("com.apple.security.cs.allow-jit")) != NULL;
    }
    CFRelease(signingInformation);
    return 0;
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
    CFArrayRef certificates = CFDictionaryGetValue(signingInformation, kSecCodeInfoCertificates);
    GuardSignatureCopyString(team, info->team_id, sizeof(info->team_id));
    GuardSignatureCopyString(signing, info->signing_id, sizeof(info->signing_id));
    if (certificates != NULL && CFArrayGetCount(certificates) > 0) {
        SecCertificateRef leaf = (SecCertificateRef)CFArrayGetValueAtIndex(certificates, 0);
        GuardSignatureCopyCertificateSha1(leaf, info->leaf_certificate_sha1,
                                          sizeof(info->leaf_certificate_sha1));
    }
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
