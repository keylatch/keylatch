package sops

import (
	"errors"
	"strings"
)

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := range gen {
			if (top>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []byte {
	out := make([]byte, 0, 2*len(hrp)+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

// bech32Decode returns the human-readable part and the data of a Bech32
// string, checksum verified and removed. The case must not be mixed.
func bech32Decode(s string) (string, []byte, error) {
	if strings.ToLower(s) != s && strings.ToUpper(s) != s {
		return "", nil, errors.New("sops: mixed-case bech32 string")
	}
	s = strings.ToLower(s)
	i := strings.LastIndexByte(s, '1')
	if i < 1 || len(s)-i < 7 {
		return "", nil, errors.New("sops: malformed bech32 string")
	}
	hrp, rest := s[:i], s[i+1:]
	data := make([]byte, len(rest))
	for j := 0; j < len(rest); j++ {
		v := strings.IndexByte(bech32Charset, rest[j])
		if v < 0 {
			return "", nil, errors.New("sops: invalid bech32 character")
		}
		data[j] = byte(v & 0x1f)
	}
	if bech32Polymod(append(bech32HRPExpand(hrp), data...)) != 1 {
		return "", nil, errors.New("sops: bech32 checksum mismatch")
	}
	return hrp, data[:len(data)-6], nil
}

// convertBits regroups 5-bit values into bytes without padding.
func convertBits(data []byte, from, to uint) ([]byte, error) {
	var acc, bits uint
	var out []byte
	maxv := uint(1)<<to - 1
	for _, v := range data {
		if uint(v)>>from != 0 {
			return nil, errors.New("sops: bech32 value out of range")
		}
		acc = acc<<from | uint(v)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte(acc>>bits&maxv&0xff))
		}
	}
	if bits >= from || acc<<(to-bits)&maxv != 0 {
		return nil, errors.New("sops: bech32 padding is not zero")
	}
	return out, nil
}
