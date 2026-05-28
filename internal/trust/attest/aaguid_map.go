package attest

// aaguidEntry holds known information about an authenticator device model.
type aaguidEntry struct {
	model string
	fips  bool
}

// aaguidMap is a static map of AAGUID strings to device metadata.
// Sources: FIDO MDS3 + vendor documentation.
// Only a representative subset is included; unknown AAGUIDs return Trusted=false.
var aaguidMap = map[string]aaguidEntry{
	// YubiKey 5 Series — NFC.
	"2fc0579f-8113-47ea-b116-bb5a8db9202a": {model: "YubiKey 5 NFC", fips: false},
	// YubiKey 5 Series — USB-A.
	"149a2021-8ef6-4133-96b8-81f8d5b7f1f5": {model: "YubiKey 5 USB-A", fips: false},
	// YubiKey 5 Series — USB-C.
	"c1f9a0bc-1dd2-404a-b27f-8e29047a43fd": {model: "YubiKey 5 USB-C", fips: false},
	// YubiKey 5 Series — NFC FIPS.
	"73bb0cd4-e502-49b8-9c6f-b59445bf720b": {model: "YubiKey 5 NFC FIPS", fips: true},
	// YubiKey 5 Series — USB-A FIPS.
	"0bb43545-fd2c-4185-87dd-feb0b2916ace": {model: "YubiKey 5 USB-A FIPS", fips: true},
	// YubiKey 5Ci.
	"c5ef55ff-ad9a-4b9f-b580-adebafe026d0": {model: "YubiKey 5Ci", fips: false},
	// SoftToken (SoftHSM) — for testing.
	"00000000-0000-0000-0000-000000000000": {model: "SoftToken", fips: false},
}
