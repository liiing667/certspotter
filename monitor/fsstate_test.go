// Copyright (C) 2026 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

package monitor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	certspotter "software.sslmate.com/src/certspotter"
	"software.sslmate.com/src/certspotter/cttypes"
	"software.sslmate.com/src/certspotter/loglist"
)

func makeTestDiscoveredCert(t *testing.T, watchItem WatchItem, dnsNames []string, ipAddrs []net.IP) *DiscoveredCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial := big.NewInt(time.Now().UnixNano())
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test.invalid"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     dnsNames,
		IPAddresses:  ipAddrs,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certInfo, err := certspotter.MakeCertInfoFromRawCert(der)
	if err != nil {
		t.Fatal(err)
	}
	if precertTBS, err := certspotter.ReconstructPrecertTBS(certInfo.TBS); err == nil {
		certInfo.TBS = precertTBS
	}

	identifiers, err := certInfo.ParseIdentifiers()
	if err != nil {
		t.Fatal(err)
	}

	return &DiscoveredCert{
		WatchItem: watchItem,
		LogEntry: &LogEntry{
			Index: 42,
			Log:   &loglist.Log{URL: "https://log.invalid/ct/v1/"},
		},
		Info:         certInfo,
		Chain:        []cttypes.ASN1Cert{der},
		TBSSHA256:    sha256.Sum256(certInfo.TBS.Raw),
		SHA256:       sha256.Sum256(der),
		PubkeySHA256: sha256.Sum256(certInfo.TBS.PublicKey.FullBytes),
		Identifiers:  identifiers,
	}
}

func newTestState(t *testing.T, saveCerts bool) (*FilesystemState, string) {
	t.Helper()
	stateDir := t.TempDir()
	cacheDir := t.TempDir()

	counterPath := filepath.Join(t.TempDir(), "notifications.log")
	scriptPath := filepath.Join(t.TempDir(), "notify.sh")
	script := "#!/bin/sh\necho \"$WATCH_ITEM $CERT_SHA256\" >> \"" + counterPath + "\"\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0777); err != nil {
		t.Fatal(err)
	}

	state := &FilesystemState{
		StateDir:  stateDir,
		CacheDir:  cacheDir,
		SaveCerts: saveCerts,
		Script:    scriptPath,
	}
	if err := state.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	return state, counterPath
}

func countNotifications(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		return 0
	}
	count := 0
	for _, line := range splitLines(string(data)) {
		if line != "" {
			count++
		}
	}
	return count
}

func splitLines(s string) []string {
	var lines []string
	current := ""
	for _, ch := range s {
		if ch == '\n' {
			lines = append(lines, current)
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

func TestNotifyCertDedupAcrossRetries(t *testing.T) {
	for _, saveCerts := range []bool{true, false} {
		t.Run(fmt.Sprintf("saveCerts=%v", saveCerts), func(t *testing.T) {
			state, counterPath := newTestState(t, saveCerts)
			item, err := ParseWatchItem("ip:192.0.2.1")
			if err != nil {
				t.Fatal(err)
			}
			cert := makeTestDiscoveredCert(t, item, nil, []net.IP{net.ParseIP("192.0.2.1")})

			ctx := context.Background()
			for i := 0; i < 3; i++ {
				if err := state.NotifyCert(ctx, cert); err != nil {
					t.Fatalf("NotifyCert attempt %d failed: %v", i, err)
				}
			}

			if got := countNotifications(t, counterPath); got != 1 {
				t.Fatalf("expected exactly 1 notification across retries, got %d", got)
			}

			// The historical marker layout must exist even with -no_save so
			// state and evidence stay consistent and certspotter-authorize
			// keeps working.
			tbsHex := hex.EncodeToString(cert.TBSSHA256[:])
			marker := filepath.Join(state.StateDir, "certs", tbsHex[0:2], "."+tbsHex+".notified")
			if _, err := os.Stat(marker); err != nil {
				t.Fatalf("notified marker missing at %s: %v", marker, err)
			}
		})
	}
}

func TestNotifyCertConcurrentDedup(t *testing.T) {
	state, counterPath := newTestState(t, false)
	item, err := ParseWatchItem("ip:192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	cert := makeTestDiscoveredCert(t, item, nil, []net.IP{net.ParseIP("192.0.2.1")})

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := state.NotifyCert(context.Background(), cert); err != nil {
				t.Errorf("NotifyCert failed: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := countNotifications(t, counterPath); got != 1 {
		t.Fatalf("expected exactly 1 notification under concurrency, got %d", got)
	}
}

func TestNotifyCertIPWatchItemIdentity(t *testing.T) {
	state, counterPath := newTestState(t, true)
	item, err := ParseWatchItem("ip:192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	cert := makeTestDiscoveredCert(t, item, nil, []net.IP{net.ParseIP("192.0.2.1")})

	if err := state.NotifyCert(context.Background(), cert); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(counterPath)
	if err != nil {
		t.Fatal(err)
	}
	if want := "ip:192.0.2.1 "; string(data)[:len(want)] != want {
		t.Fatalf("notification used wrong watch item identity: %q", data)
	}

	// The JSON evidence keeps the historical shape with a canonical IP string.
	certHex := hex.EncodeToString(cert.SHA256[:])
	jsonPath := filepath.Join(state.StateDir, "certs", certHex[0:2], certHex+".v1.json")
	jsonBytes, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var evidence map[string]any
	if err := json.Unmarshal(jsonBytes, &evidence); err != nil {
		t.Fatal(err)
	}
	ips, ok := evidence["ip_addresses"].([]any)
	if !ok || len(ips) != 1 || ips[0] != "192.0.2.1" {
		t.Fatalf("unexpected ip_addresses in JSON evidence: %v", evidence["ip_addresses"])
	}
}

func TestNotifyCertLegacyMarkerSuppresses(t *testing.T) {
	state, counterPath := newTestState(t, false)
	item, err := ParseWatchItem("example.com")
	if err != nil {
		t.Fatal(err)
	}
	cert := makeTestDiscoveredCert(t, item, []string{"example.com"}, nil)

	// Simulate a marker written by a previous version of certspotter.
	tbsHex := hex.EncodeToString(cert.TBSSHA256[:])
	tbsDir := filepath.Join(state.StateDir, "certs", tbsHex[0:2])
	if err := os.MkdirAll(tbsDir, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tbsDir, "."+tbsHex+".notified"), nil, 0666); err != nil {
		t.Fatal(err)
	}

	if err := state.NotifyCert(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	if got := countNotifications(t, counterPath); got != 0 {
		t.Fatalf("historical marker did not suppress notification, got %d", got)
	}
}
