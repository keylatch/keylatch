//go:build windows

package keys

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CNG names and flags (ncrypt.h, bcrypt.h).
const (
	providerPlatform = "Microsoft Platform Crypto Provider"
	providerSoftware = "Microsoft Software Key Storage Provider"

	ncryptMachineKeyFlag = 0x20
	ncryptPadOAEPFlag    = 0x4
	daclSecurityInfo     = 0x4
	rsaKeyBits           = 2048

	ntBadKeyset = 0x80090016
)

var (
	ncrypt                  = windows.NewLazySystemDLL("ncrypt.dll")
	procOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procSetProperty         = ncrypt.NewProc("NCryptSetProperty")
	procFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procEncrypt             = ncrypt.NewProc("NCryptEncrypt")
	procDecrypt             = ncrypt.NewProc("NCryptDecrypt")
	procFreeObject          = ncrypt.NewProc("NCryptFreeObject")
	procDeleteKey           = ncrypt.NewProc("NCryptDeleteKey")
	errNoKey                = errors.New("keys: the CNG key does not exist")
	providerTags            = []byte{1, 2}
	providerNames           = map[byte]string{1: providerPlatform, 2: providerSoftware}
	oaepHash                = windows.StringToUTF16Ptr("SHA256")
	rsaAlg                  = windows.StringToUTF16Ptr("RSA")
	lengthProp              = windows.StringToUTF16Ptr("Length")
	securityDescrProp       = windows.StringToUTF16Ptr("Security Descr")
)

type oaepPadding struct {
	hashAlg *uint16
	label   *byte
	labelN  uint32
}

func status(r uintptr) error {
	if r == 0 {
		return nil
	}
	return fmt.Errorf("keys: CNG status 0x%08x", uint32(r))
}

// CNGSealer wraps the device root with an RSA key held by CNG as a machine key.
// The Platform Crypto Provider keeps the key in the TPM when there is one; the
// software provider is the fallback. The key's DACL names only SYSTEM and the
// service, so the sealed file opens for nobody else.
type CNGSealer struct {
	KeyName string
	// ServiceSID is granted use of the key.
	ServiceSID string
}

// Name implements Sealer.
func (CNGSealer) Name() string { return "CNG machine key" }

type cngProv struct{ h uintptr }

func openProvider(name string) (cngProv, error) {
	var h uintptr
	r, _, _ := procOpenStorageProvider.Call(uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))), 0)
	return cngProv{h}, status(r)
}

func (p cngProv) free() { _, _, _ = procFreeObject.Call(p.h) }

func freeKey(h uintptr) { _, _, _ = procFreeObject.Call(h) }

func (p cngProv) open(name string) (uintptr, error) {
	var k uintptr
	r, _, _ := procOpenKey.Call(p.h, uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))), 0, ncryptMachineKeyFlag)
	if uint32(r) == ntBadKeyset {
		return 0, errNoKey
	}
	return k, status(r)
}

func (p cngProv) create(name, serviceSID string) (uintptr, error) {
	var k uintptr
	r, _, _ := procCreatePersistedKey.Call(p.h, uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(rsaAlg)),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))), 0, ncryptMachineKeyFlag)
	if err := status(r); err != nil {
		return 0, err
	}
	bits := uint32(rsaKeyBits)
	r, _, _ = procSetProperty.Call(k, uintptr(unsafe.Pointer(lengthProp)), uintptr(unsafe.Pointer(&bits)), 4, 0)
	if err := status(r); err != nil {
		freeKey(k)
		return 0, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;SY)(A;;GA;;;" + serviceSID + ")")
	if err != nil {
		freeKey(k)
		return 0, err
	}
	r, _, _ = procSetProperty.Call(k, uintptr(unsafe.Pointer(securityDescrProp)), uintptr(unsafe.Pointer(sd)), uintptr(sd.Length()), daclSecurityInfo)
	if err := status(r); err != nil {
		freeKey(k)
		return 0, err
	}
	r, _, _ = procFinalizeKey.Call(k, 0)
	if err := status(r); err != nil {
		freeKey(k)
		return 0, err
	}
	return k, nil
}

func crypt(proc *windows.LazyProc, key uintptr, in []byte) ([]byte, error) {
	pad := oaepPadding{hashAlg: oaepHash}
	var n uint32
	call := func(out *byte, size uint32) error {
		r, _, _ := proc.Call(key, uintptr(unsafe.Pointer(&in[0])), uintptr(len(in)), uintptr(unsafe.Pointer(&pad)),
			uintptr(unsafe.Pointer(out)), uintptr(size), uintptr(unsafe.Pointer(&n)), ncryptPadOAEPFlag)
		return status(r)
	}
	if err := call(nil, 0); err != nil {
		return nil, err
	}
	out := make([]byte, n)
	if err := call(&out[0], n); err != nil {
		return nil, err
	}
	return out[:n], nil
}

// Seal implements Sealer. The output starts with a byte naming the provider that
// holds the key.
func (s CNGSealer) Seal(plain []byte) ([]byte, error) {
	var lastErr error
	for _, tag := range providerTags {
		p, err := openProvider(providerNames[tag])
		if err != nil {
			lastErr = err
			continue
		}
		key, err := p.open(s.KeyName)
		if errors.Is(err, errNoKey) {
			key, err = p.create(s.KeyName, s.ServiceSID)
		}
		if err != nil {
			p.free()
			lastErr = err
			continue
		}
		ct, err := crypt(procEncrypt, key, plain)
		if err == nil {
			// A provider that encrypts but cannot decrypt (some TPM
			// configurations) would lose the root; prove the round trip first.
			var back []byte
			if back, err = crypt(procDecrypt, key, ct); err == nil && string(back) != string(plain) {
				err = errors.New("keys: the CNG round trip returned other bytes")
			}
			clear(back)
		}
		if err != nil {
			_, _, _ = procDeleteKey.Call(key, 0)
			p.free()
			lastErr = err
			continue
		}
		freeKey(key)
		p.free()
		return append([]byte{tag}, ct...), nil
	}
	return nil, lastErr
}

// Open implements Sealer.
func (s CNGSealer) Open(sealed []byte) ([]byte, error) {
	if len(sealed) < 2 || providerNames[sealed[0]] == "" {
		return nil, errors.New("keys: the sealed root is malformed")
	}
	p, err := openProvider(providerNames[sealed[0]])
	if err != nil {
		return nil, err
	}
	defer p.free()
	key, err := p.open(s.KeyName)
	if err != nil {
		return nil, err
	}
	defer freeKey(key)
	return crypt(procDecrypt, key, sealed[1:])
}
