package brokerapi

import (
	"encoding/json"
	"testing"
)

// FuzzBrokerRequest feeds arbitrary bytes to the decoder every broker request
// passes through. A frame that decodes must survive a round trip with the same
// digest, describe itself, and satisfy every bound Validate states.
func FuzzBrokerRequest(f *testing.F) {
	for _, req := range validRequests() {
		b, err := json.Marshal(req)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(`{"op":"secret.set","path":"a","value":"AAAA","proof":"` + proofHex + `"}`))
	f.Add([]byte(`{"op":"presence.begin","target":{"op":"keys.rotate"}}`))
	f.Add([]byte(`{"op":`))
	f.Add([]byte("\x00\xff{"))

	f.Fuzz(func(t *testing.T, frame []byte) {
		OpOf(frame)
		req, err := Decode(frame)
		if err != nil {
			return
		}
		digest := req.Digest()
		action, summary := req.Describe()
		if action == "" || summary == "" {
			t.Fatal("an accepted request must describe itself")
		}
		again, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("an accepted request must re-encode: %v", err)
		}
		back, err := Decode(again)
		if err != nil {
			t.Fatalf("an accepted request must decode again: %v", err)
		}
		if back.Digest() != digest {
			t.Fatal("the digest changed across a round trip")
		}
		if len(req.Value) > MaxValue || len(req.Items) > MaxItems || len(req.Path) > MaxPathLen {
			t.Fatal("an accepted request exceeds a documented bound")
		}
		if req.Target != nil && (req.Op != OpPresenceBegin || !Privileged(req.Target.Op)) {
			t.Fatal("a target is only valid on presence.begin and must be privileged")
		}
	})
}
