//go:build darwin && cgo

package keys

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#cgo CFLAGS: -Wno-deprecated-declarations
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <string.h>

static const char *klSystemKeychain = "/Library/Keychains/System.keychain";

// klLoad copies the stored secret into out (capacity cap) and returns the status.
static OSStatus klLoad(const char *svc, const char *acct, char *out, UInt32 cap, UInt32 *n) {
	SecKeychainRef kc = NULL;
	OSStatus st = SecKeychainOpen(klSystemKeychain, &kc);
	if (st != errSecSuccess) {
		return st;
	}
	UInt32 len = 0;
	void *data = NULL;
	st = SecKeychainFindGenericPassword(kc, (UInt32)strlen(svc), svc, (UInt32)strlen(acct), acct, &len, &data, NULL);
	CFRelease(kc);
	if (st != errSecSuccess) {
		return st;
	}
	if (len > cap) {
		SecKeychainItemFreeContent(NULL, data);
		return errSecBufferTooSmall;
	}
	memcpy(out, data, len);
	*n = len;
	SecKeychainItemFreeContent(NULL, data);
	return errSecSuccess;
}

// klStore adds the secret to the System keychain with an access list that
// names only the trusted binary, so the daemon reads it without a prompt and
// nothing else gets in without one.
static OSStatus klStore(const char *svc, const char *acct, const void *data, UInt32 n, const char *trusted) {
	SecKeychainRef kc = NULL;
	OSStatus st = SecKeychainOpen(klSystemKeychain, &kc);
	if (st != errSecSuccess) {
		return st;
	}
	SecTrustedApplicationRef app = NULL;
	st = SecTrustedApplicationCreateFromPath(trusted, &app);
	if (st != errSecSuccess) {
		CFRelease(kc);
		return st;
	}
	const void *apps[1] = { app };
	CFArrayRef list = CFArrayCreate(NULL, apps, 1, &kCFTypeArrayCallBacks);
	CFStringRef label = CFStringCreateWithCString(NULL, svc, kCFStringEncodingUTF8);
	SecAccessRef access = NULL;
	st = SecAccessCreate(label, list, &access);
	SecKeychainItemRef item = NULL;
	if (st == errSecSuccess) {
		st = SecKeychainAddGenericPassword(kc, (UInt32)strlen(svc), svc, (UInt32)strlen(acct), acct, n, data, &item);
	}
	if (st == errSecSuccess) {
		st = SecKeychainItemSetAccess(item, access);
		if (st != errSecSuccess) {
			SecKeychainItemDelete(item);
		}
	}
	if (item) CFRelease(item);
	if (access) CFRelease(access);
	CFRelease(label);
	CFRelease(list);
	CFRelease(app);
	CFRelease(kc);
	return st;
}
*/
import "C"

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"unsafe"
)

const errSecItemNotFound = -25300

// KeychainRoot keeps the device root as a generic password item in the System
// keychain. Its access list names only the keylatchd binary, whose designated
// requirement the keychain checks on every read, so a process of any user that
// is not keylatchd reads nothing.
type KeychainRoot struct {
	Service string
	Account string
	// Trusted is the path of the daemon binary the access list names.
	Trusted string
}

// Name implements RootStore.
func (KeychainRoot) Name() string { return "System keychain" }

// Load implements RootStore.
func (k KeychainRoot) Load() ([]byte, error) {
	svc, acct := C.CString(k.Service), C.CString(k.Account)
	defer C.free(unsafe.Pointer(svc))
	defer C.free(unsafe.Pointer(acct))
	buf := make([]byte, 256)
	defer clear(buf)
	var n C.UInt32
	st := C.klLoad(svc, acct, (*C.char)(unsafe.Pointer(&buf[0])), C.UInt32(len(buf)), &n)
	switch {
	case st == errSecItemNotFound:
		return nil, fmt.Errorf("%w: no keychain item %s", ErrNoRoot, k.Service)
	case st != 0:
		return nil, fmt.Errorf("%w: keychain status %d", ErrNoRoot, int(st))
	}
	root := make([]byte, hex.DecodedLen(int(n)))
	if _, err := hex.Decode(root, buf[:n]); err != nil || len(root) < rootMinLen {
		clear(root)
		return nil, ErrNoRoot
	}
	return root, nil
}

// Create implements RootStore.
func (k KeychainRoot) Create(rd io.Reader) (bool, error) {
	if root, err := k.Load(); err == nil {
		clear(root)
		return false, nil
	} else if !errors.Is(err, ErrNoRoot) {
		return false, err
	}
	if rd == nil {
		rd = rand.Reader
	}
	secret := make([]byte, keyLen)
	defer clear(secret)
	if _, err := io.ReadFull(rd, secret); err != nil {
		return false, fmt.Errorf("keys: generate the device root: %w", err)
	}
	text := []byte(hex.EncodeToString(secret))
	defer clear(text)
	svc, acct, trusted := C.CString(k.Service), C.CString(k.Account), C.CString(k.Trusted)
	defer C.free(unsafe.Pointer(svc))
	defer C.free(unsafe.Pointer(acct))
	defer C.free(unsafe.Pointer(trusted))
	if st := C.klStore(svc, acct, unsafe.Pointer(&text[0]), C.UInt32(len(text)), trusted); st != 0 {
		return false, fmt.Errorf("keys: store the device root in the System keychain: status %d", int(st))
	}
	return true, nil
}

// DefaultRootStore returns the System keychain item for the daemon binary.
func DefaultRootStore(_ string, daemon string, _ func(string) error) RootStore {
	return KeychainRoot{Service: "dev.keylatch.broker.root", Account: CredentialName, Trusted: daemon}
}
