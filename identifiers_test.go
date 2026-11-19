// Copyright (C) 2026 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

package certspotter

import (
	"net"
	"testing"
)

func TestCanonicalIPAddr(t *testing.T) {
	rawV4 := net.IP([]byte{192, 0, 2, 1})
	parsedV4 := net.ParseIP("192.0.2.1")
	mappedV4 := net.ParseIP("::ffff:192.0.2.1")

	if got := canonicalIPAddr(rawV4); len(got) != 16 {
		t.Fatalf("canonicalIPAddr(raw v4) length = %d, want 16", len(got))
	}
	if !canonicalIPAddr(rawV4).Equal(canonicalIPAddr(parsedV4)) {
		t.Fatal("raw and parsed IPv4 addresses canonicalize differently")
	}
	if !canonicalIPAddr(mappedV4).Equal(canonicalIPAddr(rawV4)) {
		t.Fatal("IPv4-mapped IPv6 address canonicalizes differently from IPv4")
	}
	if canonicalIPAddr(nil) != nil {
		t.Fatal("canonicalIPAddr(nil) is not nil")
	}
}

func TestIdentifiersDedupCanonicalIPs(t *testing.T) {
	ids := NewIdentifiers()

	// Same address arriving via different encodings (raw 4-byte IP SAN,
	// parsed DNS-SAN/CN string, and an IPv4-mapped form) must collapse to a
	// single identity.
	ids.AddIPAddress(net.IP([]byte{192, 0, 2, 1}))
	ids.addDnsSANfinal([]byte("192.0.2.1"))
	ids.AddCN("192.0.2.1")
	ids.AddIPAddress(net.ParseIP("::ffff:192.0.2.1"))

	if len(ids.IPAddrs) != 1 {
		t.Fatalf("expected a single canonical IP address, got %d: %v", len(ids.IPAddrs), ids.IPAddrs)
	}
	for _, ipaddr := range ids.IPAddrs {
		if len(ipaddr) != 16 {
			t.Fatalf("stored IP address is not canonical 16-byte form: %d bytes", len(ipaddr))
		}
		if ipaddr.String() != "192.0.2.1" {
			t.Fatalf("stored IP address = %q, want %q", ipaddr.String(), "192.0.2.1")
		}
	}
}

func TestIdentifiersDistinctIPs(t *testing.T) {
	ids := NewIdentifiers()
	ids.AddIPAddress(net.ParseIP("192.0.2.1"))
	ids.AddIPAddress(net.ParseIP("192.0.2.2"))
	ids.AddIPAddress(net.ParseIP("2001:db8::1"))
	if len(ids.IPAddrs) != 3 {
		t.Fatalf("expected 3 distinct IP addresses, got %d", len(ids.IPAddrs))
	}
}

func TestIdentifiersIPInDNSSAN(t *testing.T) {
	ids := NewIdentifiers()
	ids.AddDnsSAN([]byte("198.51.100.42"))
	if len(ids.DNSNames) != 0 {
		t.Fatalf("an IP address in a DNS SAN must not be treated as a DNS name: %v", ids.DNSNames)
	}
	if len(ids.IPAddrs) != 1 || ids.IPAddrs[0].String() != "198.51.100.42" {
		t.Fatalf("IP in DNS SAN not extracted correctly: %v", ids.IPAddrs)
	}
}
