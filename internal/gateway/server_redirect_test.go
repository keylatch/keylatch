package gateway

import (
	"net/http"
	"net/url"
	"testing"
)

func TestProviderRedirectPolicy(t *testing.T) {
	mustReq := func(raw string) *http.Request {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Request{URL: u}
	}
	hops := func(n int) []*http.Request {
		out := make([]*http.Request, n)
		for i := range out {
			out[i] = mustReq("https://api.example.com/start")
		}
		return out
	}

	tests := []struct {
		name    string
		target  string
		via     []*http.Request
		wantErr error
		anyErr  bool
	}{
		{name: "same origin allowed", target: "https://api.example.com/next", via: hops(1)},
		{name: "host match is case-insensitive", target: "https://API.Example.COM/next", via: hops(1)},
		{name: "different host refused", target: "https://other.example.com/next", via: hops(1), wantErr: http.ErrUseLastResponse},
		{name: "port mismatch refused", target: "https://api.example.com:8443/next", via: hops(1), wantErr: http.ErrUseLastResponse},
		{name: "scheme downgrade refused", target: "http://api.example.com/next", via: hops(1), wantErr: http.ErrUseLastResponse},
		{name: "ninth hop allowed", target: "https://api.example.com/next", via: hops(9)},
		{name: "tenth hop capped", target: "https://api.example.com/next", via: hops(10), anyErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := providerRedirectPolicy(mustReq(tc.target), tc.via)
			switch {
			case tc.anyErr:
				if err == nil || err == http.ErrUseLastResponse {
					t.Fatalf("want redirect-cap error, got %v", err)
				}
			case err != tc.wantErr:
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}
