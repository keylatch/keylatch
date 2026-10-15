//go:build darwin && cgo

package presence

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework LocalAuthentication
#import <LocalAuthentication/LocalAuthentication.h>
#include <stdlib.h>
#include <string.h>

// klAuthenticate returns 0 when the user authenticated, 1 when they did not
// and 2 when the policy cannot be evaluated on this machine. errOut receives
// a malloc'd description for non-zero results.
static int klAuthenticate(const char *reason, char **errOut) {
	LAContext *ctx = [[LAContext alloc] init];
	NSError *err = nil;
	if (![ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&err]) {
		*errOut = strdup([[err localizedDescription] UTF8String]);
		return 2;
	}
	dispatch_semaphore_t sem = dispatch_semaphore_create(0);
	__block int rc = 1;
	__block NSString *msg = nil;
	[ctx evaluatePolicy:LAPolicyDeviceOwnerAuthentication
	    localizedReason:[NSString stringWithUTF8String:reason]
	              reply:^(BOOL ok, NSError *e) {
		if (ok) {
			rc = 0;
		} else {
			msg = [e localizedDescription];
		}
		dispatch_semaphore_signal(sem);
	}];
	dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
	if (msg != nil) {
		*errOut = strdup([msg UTF8String]);
	}
	return rc;
}
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"unsafe"
)

type localAuth struct{}

// platformMethod asks macOS for Touch ID or the account password.
func platformMethod() Method { return localAuth{} }

func (localAuth) Name() string { return "localauth" }

func (localAuth) Confirm(_ context.Context, action Action, summary string) error {
	reason := C.CString(fmt.Sprintf("approve %s: %s", action, summary))
	defer C.free(unsafe.Pointer(reason))
	var msg *C.char
	rc := C.klAuthenticate(reason, &msg)
	text := ""
	if msg != nil {
		text = C.GoString(msg)
		C.free(unsafe.Pointer(msg))
	}
	switch rc {
	case 0:
		return nil
	case 2:
		return fmt.Errorf("%w: %s", ErrUnavailable, text)
	}
	return errors.New(text)
}
