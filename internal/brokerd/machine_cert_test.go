//go:build unix

package brokerd

import (
	"crypto/x509"
	"net"
	"slices"
	"testing"
	"time"
)

type fakeAddr struct{ s string }

func (a fakeAddr) Network() string { return "ip+net" }
func (a fakeAddr) String() string  { return a.s }

func TestServerCertificateIsRenewedBeforeItExpires(t *testing.T) {
	h := newHarness(t, nil)
	src := &certSource{s: h.srv, hosts: []string{"localhost", "10.0.0.5"}}
	first, err := src.get()
	if err != nil {
		t.Fatal(err)
	}
	again, _ := src.get()
	if again != first {
		t.Fatal("a fresh certificate was reissued")
	}
	leaf, err := x509.ParseCertificate(first.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.NotAfter.Before(h.now.Add(serverCertLife + time.Hour)) {
		t.Fatalf("the certificate lives until %s", leaf.NotAfter)
	}

	*h.now = h.now.Add(serverCertLife - serverCertRenew/2)
	renewed, err := src.get()
	if err != nil || renewed == first {
		t.Fatalf("a certificate close to its end was kept: %v", err)
	}
	*h.now = h.now.Add(2 * serverCertLife)
	late, err := src.get()
	if err != nil || late == renewed {
		t.Fatalf("an expired certificate was kept: %v", err)
	}
	leaf, _ = x509.ParseCertificate(late.Certificate[0])
	if !leaf.NotAfter.After(*h.now) || !slices.ContainsFunc(leaf.IPAddresses, func(ip net.IP) bool { return ip.String() == "10.0.0.5" }) {
		t.Fatalf("the reissued certificate: until %s, IPs %v", leaf.NotAfter, leaf.IPAddresses)
	}
}

func TestListenerHostsForWildcardAndSpecificBinds(t *testing.T) {
	prev := interfaceAddrs
	interfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("10.1.2.3"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
			&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
			fakeAddr{"not an ipnet"},
		}, nil
	}
	defer func() { interfaceAddrs = prev }()

	specific := listenerHosts("192.168.9.9:7443")
	if !slices.Contains(specific, "192.168.9.9") || slices.Contains(specific, "10.1.2.3") {
		t.Fatalf("a specific bind = %v", specific)
	}
	for _, addr := range []string{"0.0.0.0:7443", "[::]:7443", ":7443"} {
		hosts := listenerHosts(addr)
		if !slices.Contains(hosts, "10.1.2.3") || slices.Contains(hosts, "0.0.0.0") || slices.Contains(hosts, "::") || slices.Contains(hosts, "fe80::1") || slices.Contains(hosts, "") {
			t.Errorf("%s: hosts = %v", addr, hosts)
		}
	}
	interfaceAddrs = func() ([]net.Addr, error) { return nil, net.ErrClosed }
	if hosts := listenerHosts("0.0.0.0:1"); !slices.Contains(hosts, "localhost") {
		t.Fatalf("without interfaces = %v", hosts)
	}
}
