//go:build darwin && cgo

package kek

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework Security -framework LocalAuthentication
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <stdlib.h>
#include <string.h>

static int klIdentity(int operation, int noPrompt, const char *account, const void *input, int inputLen, void **output, int *outputLen) {
	@autoreleasepool {
		LAContext *authentication = [[LAContext alloc] init];
		authentication.localizedReason = @"Access the Keylatch vault identity";
		dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0));
		dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, 60 * NSEC_PER_SEC), DISPATCH_TIME_FOREVER, 0);
		dispatch_source_set_event_handler(timer, ^{ [authentication invalidate]; });
		dispatch_resume(timer);
		NSMutableDictionary *query = [@{
			(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
			(__bridge id)kSecAttrService: @"keylatch-vault-kek",
			(__bridge id)kSecAttrAccount: [NSString stringWithUTF8String:account],
			(__bridge id)kSecUseDataProtectionKeychain: @YES,
			(__bridge id)kSecUseAuthenticationContext: authentication
		} mutableCopy];
		if (noPrompt) query[(__bridge id)kSecUseAuthenticationUI] = (__bridge id)kSecUseAuthenticationUIFail;
		OSStatus status = errSecParam;
		if (operation == 0) {
			query[(__bridge id)kSecReturnData] = @YES;
			query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
			CFTypeRef result = NULL;
			status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
			if (status == errSecSuccess) {
				if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) {
					status = errSecDecode;
				} else {
					CFDataRef data = (CFDataRef)result;
					CFIndex length = CFDataGetLength(data);
					if (length != 64) {
						status = errSecDecode;
					} else {
						*output = malloc((size_t)length);
						if (*output == NULL) {
							status = errSecAllocate;
						} else {
							memcpy(*output, CFDataGetBytePtr(data), (size_t)length);
							*outputLen = (int)length;
						}
					}
				}
			}
			if (result != NULL) CFRelease(result);
		} else if (operation == 1) {
			CFErrorRef error = NULL;
			SecAccessControlRef access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
				kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAccessControlUserPresence, &error);
			if (access != NULL) {
				NSData *data = [NSData dataWithBytes:input length:(NSUInteger)inputLen];
				NSDictionary *attributes = @{
					(__bridge id)kSecAttrAccessControl: (__bridge id)access,
					(__bridge id)kSecValueData: data
				};
				NSMutableDictionary *addition = [query mutableCopy];
				[addition addEntriesFromDictionary:attributes];
				status = SecItemAdd((__bridge CFDictionaryRef)addition, NULL);
				if (status == errSecDuplicateItem) {
					status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attributes);
				}
				CFRelease(access);
			}
			if (error != NULL) CFRelease(error);
		} else if (operation == 2) {
			status = SecItemDelete((__bridge CFDictionaryRef)query);
		}
		dispatch_source_cancel(timer);
		[authentication invalidate];
		return (int)status;
	}
}

static void klIdentityFree(void *data, int length) {
	volatile unsigned char *bytes = (volatile unsigned char *)data;
	for (int i = 0; i < length; i++) bytes[i] = 0;
	free(data);
}
*/
import "C"

import (
	"context"
	"encoding/hex"
	"fmt"
	"unsafe"

	"github.com/keylatch/keylatch/internal/presence"
)

type nativeKeychainIdentityStore struct{ noPrompt bool }

func newMacOSIdentityStore() IdentityStore {
	return &protectedIdentityStore{
		native: nativeKeychainIdentityStore{},
		legacy: &keychainIdentityStore{bin: "/usr/bin/security", run: execIdentityRunner},
		confirm: func(account string) error {
			_, err := presence.Require(context.Background(), presence.ActionKeysRewrap,
				"Protect the existing Keylatch vault identity "+account+" with macOS user presence")
			return err
		},
	}
}

func (nativeKeychainIdentityStore) Name() string { return "macos-keychain" }

func (s nativeKeychainIdentityStore) call(operation int, account string, input []byte) ([]byte, error) {
	if err := validAccount(account); err != nil {
		return nil, err
	}
	name := C.CString(account)
	defer C.free(unsafe.Pointer(name))
	var data unsafe.Pointer
	if len(input) != 0 {
		data = C.CBytes(input)
		defer C.klIdentityFree(data, C.int(len(input)))
	}
	var output unsafe.Pointer
	var length C.int
	var noPrompt C.int
	if s.noPrompt {
		noPrompt = 1
	}
	status := C.klIdentity(C.int(operation), noPrompt, name, data, C.int(len(input)), &output, &length)
	if output != nil {
		defer C.klIdentityFree(output, length)
	}
	if status == C.errSecItemNotFound {
		return nil, ErrIdentityNotFound
	}
	if status != C.errSecSuccess {
		return nil, fmt.Errorf("native keychain identity operation failed (OSStatus %d)", int(status))
	}
	if output != nil {
		return C.GoBytes(output, length), nil
	}
	return nil, nil
}

func (s nativeKeychainIdentityStore) Load(account string) ([]byte, error) {
	data, err := s.call(0, account, nil)
	if err != nil {
		return nil, err
	}
	defer zero(data)
	return decodeIdentity(data)
}

func (s nativeKeychainIdentityStore) Store(account string, identity []byte) error {
	if len(identity) != identitySize {
		return fmt.Errorf("native keychain identity: expected %d bytes", identitySize)
	}
	encoded := make([]byte, hex.EncodedLen(len(identity)))
	hex.Encode(encoded, identity)
	defer zero(encoded)
	_, err := s.call(1, account, encoded)
	return err
}

func (s nativeKeychainIdentityStore) Delete(account string) error {
	_, err := s.call(2, account, nil)
	return err
}
