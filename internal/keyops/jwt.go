package keyops

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
)

type jwsHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

// SignJWT returns a compact JWS over claims, which must be a JSON object.
func SignJWT(alg string, key, claims []byte, kid string) ([]byte, error) {
	if !algorithmFits(OpJWTSign, alg) {
		return nil, errors.New("algorithm cannot sign a JWT")
	}
	claims = bytes.TrimSpace(claims)
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(claims, &obj); err != nil || obj == nil {
		return nil, errors.New("claims must be a JSON object")
	}
	hdr, err := json.Marshal(jwsHeader{Alg: alg, Typ: "JWT", Kid: kid})
	if err != nil {
		return nil, err
	}
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(hdr) + "." + enc.EncodeToString(claims)
	sig, err := Sign(alg, key, []byte(signing), true)
	if err != nil {
		return nil, err
	}
	return []byte(signing + "." + enc.EncodeToString(sig)), nil
}
