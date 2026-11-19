// Copyright (C) 2026 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

package monitor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/certspotter"
)

func mustParseWatchItem(t *testing.T, str string) WatchItem {
	t.Helper()
	item, err := ParseWatchItem(str)
	if err != nil {
		t.Fatalf("ParseWatchItem(%q) returned unexpected error: %v", str, err)
	}
	return item
}

func mustRejectWatchItem(t *testing.T, str string) {
	t.Helper()
	if _, err := ParseWatchItem(str); err == nil {
		t.Fatalf("ParseWatchItem(%q) unexpectedly succeeded; ambiguous configuration must fail closed", str)
	}
}

func TestParseWatchItemIP(t *testing.T) {
	for _, input := range []string{"ip:192.0.2.1"} {
		item := mustParseWatchItem(t, input)
		if item.ipaddr == nil {
			t.Fatalf("ParseWatchItem(%q) did not produce an IP watch item", input)
		}
		if got := item.String(); got != "ip:192.0.2.1" {
			t.Fatalf("String() = %q, want %q", got, "ip:192.0.2.1")
		}
	}

	item := mustParseWatchItem(t, "ip:2001:db8::1")
	if got := item.String(); got != "ip:2001:db8::1" {
		t.Fatalf("String() = %q, want %q", got, "ip:2001:db8::1")
	}

	// IPv4-mapped IPv6 and plain IPv4 are the same identity.
	mapped := mustParseWatchItem(t, "ip:::ffff:192.0.2.1")
	plain := mustParseWatchItem(t, "ip:192.0.2.1")
	if !mapped.ipaddr.Equal(plain.ipaddr) {
		t.Fatalf("mapped and plain IPv4 watch items have different identities: %v vs %v", mapped.ipaddr, plain.ipaddr)
	}

	mustRejectWatchItem(t, "ip:not-an-address")
	mustRejectWatchItem(t, "ip:192.0.2.0/24")

	// A bare IP literal is ambiguous and must fail closed.
	mustRejectWatchItem(t, "192.0.2.1")
	mustRejectWatchItem(t, "2001:db8::1")
}

func TestParseWatchItemDNSBackwardsCompat(t *testing.T) {
	item := mustParseWatchItem(t, "example.com")
	if item.ipaddr != nil {
		t.Fatalf("DNS watch item unexpectedly has an IP address")
	}
	if got := item.String(); got != "example.com" {
		t.Fatalf("String() = %q, want %q", got, "example.com")
	}

	suffix := mustParseWatchItem(t, ".example.com")
	if !suffix.acceptSuffix || suffix.String() != ".example.com" {
		t.Fatalf("suffix watch item round trip failed: %+v", suffix)
	}

	root := mustParseWatchItem(t, ".")
	if !root.acceptSuffix || len(root.domain) != 0 {
		t.Fatalf("root watch item not parsed correctly: %+v", root)
	}

	// valid_at parameters continue to be accepted for backwards compatibility.
	compat := mustParseWatchItem(t, "example.com valid_at:2020-01-01")
	if compat.String() != "example.com" {
		t.Fatalf("valid_at compatibility broken: %q", compat.String())
	}

	mustRejectWatchItem(t, "example.com unknown_param")
}

func TestWatchListMatchesIP(t *testing.T) {
	list := WatchList{
		mustParseWatchItem(t, "ip:192.0.2.1"),
		mustParseWatchItem(t, "ip:2001:db8::1"),
	}

	// 4-byte (on-the-wire IPv4 SAN) and 16-byte encodings must both match.
	identifiers := &certspotter.Identifiers{
		IPAddrs: []net.IP{
			net.IPv4(192, 0, 2, 1),
			net.ParseIP("2001:db8::1"),
		},
	}
	matched, item := list.Matches(identifiers)
	if !matched {
		t.Fatal("IP-only certificate did not match the watch list")
	}
	if item.String() != "ip:192.0.2.1" {
		t.Fatalf("matched watch item = %q, want %q", item.String(), "ip:192.0.2.1")
	}

	nonMatching := &certspotter.Identifiers{IPAddrs: []net.IP{net.ParseIP("198.51.100.7")}}
	if matched, _ := list.Matches(nonMatching); matched {
		t.Fatal("unrelated IP address unexpectedly matched")
	}
}

func TestWatchListMatchesDNSStillWorks(t *testing.T) {
	list := WatchList{
		mustParseWatchItem(t, ".example.com"),
		mustParseWatchItem(t, "ip:192.0.2.1"),
	}

	identifiers := &certspotter.Identifiers{
		DNSNames: []string{"foo.example.com"},
		IPAddrs:  []net.IP{net.ParseIP("198.51.100.7")},
	}
	matched, item := list.Matches(identifiers)
	if !matched {
		t.Fatal("DNS name did not match the watch list")
	}
	if item.ipaddr != nil {
		t.Fatalf("DNS certificate matched an IP watch item: %q", item.String())
	}
	if item.String() != ".example.com" {
		t.Fatalf("matched watch item = %q, want %q", item.String(), ".example.com")
	}
}

func TestWatchListIPAndDNSDoNotShareIdentity(t *testing.T) {
	// A certificate carrying only an IP must never match a DNS watch item,
	// and a certificate carrying only a DNS name must never match an IP item.
	list := WatchList{
		mustParseWatchItem(t, "example.com"),
		mustParseWatchItem(t, "ip:192.0.2.1"),
	}

	if matched, _ := list.Matches(&certspotter.Identifiers{IPAddrs: []net.IP{net.ParseIP("192.0.2.1")}}); !matched {
		t.Fatal("IP certificate failed to match its own IP watch item")
	}
	if matched, item := list.Matches(&certspotter.Identifiers{DNSNames: []string{"example.com"}}); !matched || item.String() != "example.com" {
		t.Fatalf("DNS certificate matched the wrong item: %v", item)
	}
}

func TestReadWatchListRejectsAmbiguous(t *testing.T) {
	_, err := ReadWatchList(strings.NewReader("example.com\n192.0.2.1\n"))
	if err == nil {
		t.Fatal("ReadWatchList accepted an ambiguous bare IP literal")
	}
}

func TestWatchItemRoundTrip(t *testing.T) {
	cases := []string{"example.com", ".example.com", "ip:192.0.2.1", "ip:2001:db8::1"}
	for _, str := range cases {
		item := mustParseWatchItem(t, str)
		if item.String() != str {
			t.Fatalf("round trip failed: %q -> %q", str, item.String())
		}
	}

	// Internal fields of a DNS item keep their historical shape.
	item := mustParseWatchItem(t, "foo.example.com")
	if !reflect.DeepEqual(item.domain, []string{"foo", "example", "com"}) {
		t.Fatalf("unexpected domain labels: %#v", item.domain)
	}
}

// End-to-end check that a real, parsed IP-only certificate matches an IP
// watch item through the same code path used for log entries.
func TestWatchListMatchesParsedIPOnlyCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "192.0.2.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(192, 0, 2, 1)},
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certInfo, err := certspotter.MakeCertInfoFromRawCert(der)
	if err != nil {
		t.Fatal(err)
	}
	identifiers, err := certInfo.ParseIdentifiers()
	if err != nil {
		t.Fatal(err)
	}

	list := WatchList{
		mustParseWatchItem(t, "ip:192.0.2.1"),
		mustParseWatchItem(t, "example.com"),
	}
	matched, item := list.Matches(identifiers)
	if !matched {
		t.Fatal("IP-only certificate failed to match the watch list")
	}
	if item.String() != "ip:192.0.2.1" {
		t.Fatalf("matched item = %q, want %q", item.String(), "ip:192.0.2.1")
	}

	// A different watched IP must not match.
	other := WatchList{mustParseWatchItem(t, "ip:198.51.100.7")}
	if matched, _ := other.Matches(identifiers); matched {
		t.Fatal("certificate matched an unrelated IP watch item")
	}
}
