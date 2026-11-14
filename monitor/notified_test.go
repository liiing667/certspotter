// Copyright (C) 2025 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"software.sslmate.com/src/certspotter"
	"software.sslmate.com/src/certspotter/cttypes"
	"software.sslmate.com/src/certspotter/loglist"
)

// writeFakeNotifyScript installs a fake notification delivery script that
// appends a line to a count file every time it is invoked.  If exitCode is
// non-zero, the script simulates a delivery failure.
func writeFakeNotifyScript(t *testing.T, dir string, exitCode int) (scriptPath string, countPath string) {
	t.Helper()
	scriptPath = filepath.Join(dir, "notify.sh")
	countPath = filepath.Join(dir, "notify.count")
	script := "#!/bin/sh\n"
	if exitCode != 0 {
		script += "exit 1\n"
	} else {
		script += "echo \"$WATCH_ITEM $TBS_SHA256\" >> '" + countPath + "'\n"
	}
	if err := os.WriteFile(scriptPath, []byte(script), 0777); err != nil {
		t.Fatal(err)
	}
	return scriptPath, countPath
}

func countDeliveries(t *testing.T, countPath string) []string {
	t.Helper()
	data, err := os.ReadFile(countPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func newTestState(t *testing.T, stateDir string, scriptPath string) *FilesystemState {
	t.Helper()
	state := &FilesystemState{
		StateDir: stateDir,
		CacheDir: filepath.Join(stateDir, "cache"),
		Script:   scriptPath,
	}
	if err := state.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	return state
}

func mustWatchItem(t *testing.T, str string) WatchItem {
	t.Helper()
	item, err := ParseWatchItem(str)
	if err != nil {
		t.Fatal(err)
	}
	return item
}

// makeTestCert builds a fake discovered certificate.  tbsSeed determines the
// TBS fingerprint (shared by a precertificate and its final certificate);
// leafSeed determines the leaf fingerprint.
func makeTestCert(watchItem WatchItem, tbsSeed string, leafSeed string) *DiscoveredCert {
	tbsHash := sha256.Sum256([]byte("tbs:" + tbsSeed))
	leafHash := sha256.Sum256([]byte("leaf:" + leafSeed))
	pubkeyHash := sha256.Sum256([]byte("pubkey:" + tbsSeed))
	parseErr := errors.New("test parse error")
	return &DiscoveredCert{
		WatchItem: watchItem,
		LogEntry: &LogEntry{
			Index: 7,
			Log:   &loglist.Log{URL: "https://ctlog.example.com"},
		},
		Info: &certspotter.CertInfo{
			ValidityParseError:     parseErr,
			SubjectParseError:      parseErr,
			IssuerParseError:       parseErr,
			SerialNumberParseError: parseErr,
		},
		Chain:        []cttypes.ASN1Cert{[]byte("fake leaf " + leafSeed)},
		TBSSHA256:    tbsHash,
		SHA256:       leafHash,
		PubkeySHA256: pubkeyHash,
		Identifiers:  &certspotter.Identifiers{DNSNames: []string{"www.example.com"}},
	}
}

func loadLedgerRecord(t *testing.T, state *FilesystemState, watchItem WatchItem, tbsSHA256 [32]byte) *notificationRecord {
	t.Helper()
	recordPath := state.notificationRecordPath(watchItem, tbsSHA256)
	data, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("expected ledger record at %s: %v", recordPath, err)
	}
	record := new(notificationRecord)
	if err := json.Unmarshal(data, record); err != nil {
		t.Fatalf("ledger record %s is not valid JSON: %v", recordPath, err)
	}
	return record
}

func hasLedgerRecord(state *FilesystemState, watchItem WatchItem, tbsSHA256 [32]byte) bool {
	_, err := os.Lstat(state.notificationRecordPath(watchItem, tbsSHA256))
	return err == nil
}

func TestNotifyCertRecordedOnce(t *testing.T) {
	stateDir := t.TempDir()
	scriptPath, countPath := writeFakeNotifyScript(t, stateDir, 0)
	state := newTestState(t, stateDir, scriptPath)
	item := mustWatchItem(t, ".example.com")

	precert := makeTestCert(item, "same-tbs", "precert-leaf")
	finalCert := makeTestCert(item, "same-tbs", "final-leaf")

	if err := state.NotifyCert(context.Background(), precert); err != nil {
		t.Fatal(err)
	}
	// the same certificate rediscovered (e.g. as the final certificate in
	// another log) must not be notified about again
	if err := state.NotifyCert(context.Background(), finalCert); err != nil {
		t.Fatal(err)
	}

	if deliveries := countDeliveries(t, countPath); len(deliveries) != 1 {
		t.Fatalf("expected exactly 1 delivery, got %d: %v", len(deliveries), deliveries)
	}

	record := loadLedgerRecord(t, state, item, precert.TBSSHA256)
	if record.WatchItem != item.String() {
		t.Errorf("recorded watch item = %q, want %q", record.WatchItem, item.String())
	}
	if record.TBSSHA256 != hex.EncodeToString(precert.TBSSHA256[:]) {
		t.Errorf("recorded TBS fingerprint = %q, want %x", record.TBSSHA256, precert.TBSSHA256)
	}
	if record.CertSHA256 != hex.EncodeToString(precert.SHA256[:]) {
		t.Errorf("recorded cert fingerprint = %q, want %x", record.CertSHA256, precert.SHA256)
	}
	if record.NotifiedAt.IsZero() {
		t.Error("recorded notification time is zero")
	}
}

func TestNotifyCertDistinctCertificatesNotMerged(t *testing.T) {
	stateDir := t.TempDir()
	scriptPath, countPath := writeFakeNotifyScript(t, stateDir, 0)
	state := newTestState(t, stateDir, scriptPath)
	item := mustWatchItem(t, ".example.com")

	if err := state.NotifyCert(context.Background(), makeTestCert(item, "tbs-one", "leaf-one")); err != nil {
		t.Fatal(err)
	}
	if err := state.NotifyCert(context.Background(), makeTestCert(item, "tbs-two", "leaf-two")); err != nil {
		t.Fatal(err)
	}

	if deliveries := countDeliveries(t, countPath); len(deliveries) != 2 {
		t.Fatalf("expected 2 deliveries for distinct certificates, got %d: %v", len(deliveries), deliveries)
	}
}

func TestNotifyCertDistinctWatchItems(t *testing.T) {
	stateDir := t.TempDir()
	scriptPath, countPath := writeFakeNotifyScript(t, stateDir, 0)
	state := newTestState(t, stateDir, scriptPath)

	cert := makeTestCert(mustWatchItem(t, ".example.com"), "same-tbs", "same-leaf")
	if err := state.NotifyCert(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	otherItemCert := makeTestCert(mustWatchItem(t, "example.com"), "same-tbs", "same-leaf")
	if err := state.NotifyCert(context.Background(), otherItemCert); err != nil {
		t.Fatal(err)
	}

	if deliveries := countDeliveries(t, countPath); len(deliveries) != 2 {
		t.Fatalf("expected 2 deliveries for distinct watch items, got %d: %v", len(deliveries), deliveries)
	}
}

func TestNotifyCertRetryAfterFailure(t *testing.T) {
	stateDir := t.TempDir()
	scriptPath, countPath := writeFakeNotifyScript(t, stateDir, 1)
	state := newTestState(t, stateDir, scriptPath)
	item := mustWatchItem(t, ".example.com")
	cert := makeTestCert(item, "some-tbs", "some-leaf")

	if err := state.NotifyCert(context.Background(), cert); err == nil {
		t.Fatal("expected error from failing notify script")
	}
	if hasLedgerRecord(state, item, cert.TBSSHA256) {
		t.Fatal("ledger record must not be written when delivery fails")
	}

	// fix the script and retry; the notification must be delivered
	scriptPath, countPath = writeFakeNotifyScript(t, stateDir, 0)
	state.Script = scriptPath
	if err := state.NotifyCert(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	if deliveries := countDeliveries(t, countPath); len(deliveries) != 1 {
		t.Fatalf("expected 1 delivery after retry, got %d: %v", len(deliveries), deliveries)
	}
	if !hasLedgerRecord(state, item, cert.TBSSHA256) {
		t.Fatal("ledger record must be written after successful delivery")
	}
}

func TestNotifyCertLedgerPersistsAcrossRestart(t *testing.T) {
	stateDir := t.TempDir()
	scriptPath, countPath := writeFakeNotifyScript(t, stateDir, 0)
	item := mustWatchItem(t, ".example.com")
	cert := makeTestCert(item, "some-tbs", "some-leaf")

	if err := newTestState(t, stateDir, scriptPath).NotifyCert(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	// simulate a restart by constructing a fresh FilesystemState on the same directory
	if err := newTestState(t, stateDir, scriptPath).NotifyCert(context.Background(), cert); err != nil {
		t.Fatal(err)
	}

	if deliveries := countDeliveries(t, countPath); len(deliveries) != 1 {
		t.Fatalf("expected exactly 1 delivery across restarts, got %d: %v", len(deliveries), deliveries)
	}
}

func TestNotifyCertConcurrentDiscovery(t *testing.T) {
	stateDir := t.TempDir()
	scriptPath, countPath := writeFakeNotifyScript(t, stateDir, 0)
	state := newTestState(t, stateDir, scriptPath)
	item := mustWatchItem(t, ".example.com")

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = state.NotifyCert(context.Background(), makeTestCert(item, "same-tbs", "same-leaf"))
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	if deliveries := countDeliveries(t, countPath); len(deliveries) != 1 {
		t.Fatalf("expected exactly 1 delivery for concurrent discoveries, got %d: %v", len(deliveries), deliveries)
	}
}

func TestNotifyCertLegacyNotifiedMarker(t *testing.T) {
	stateDir := t.TempDir()
	scriptPath, countPath := writeFakeNotifyScript(t, stateDir, 0)
	state := newTestState(t, stateDir, scriptPath)
	item := mustWatchItem(t, ".example.com")
	cert := makeTestCert(item, "some-tbs", "some-leaf")

	// markers written by previous certspotter versions must still suppress notifications
	tbsFingerprint := hex.EncodeToString(cert.TBSSHA256[:])
	tbsDir := filepath.Join(stateDir, "certs", tbsFingerprint[0:2])
	if err := os.MkdirAll(tbsDir, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tbsDir, "."+tbsFingerprint+".notified"), nil, 0666); err != nil {
		t.Fatal(err)
	}

	if err := state.NotifyCert(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	if deliveries := countDeliveries(t, countPath); len(deliveries) != 0 {
		t.Fatalf("expected no deliveries with legacy marker present, got %d: %v", len(deliveries), deliveries)
	}
}
