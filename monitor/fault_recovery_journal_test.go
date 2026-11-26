package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"software.sslmate.com/src/certspotter"
	"software.sslmate.com/src/certspotter/ctclient"
	"software.sslmate.com/src/certspotter/cttypes"
	"software.sslmate.com/src/certspotter/loglist"
	"software.sslmate.com/src/certspotter/merkletree"
)

func faultRecoveryCert(t *testing.T) *DiscoveredCert {
	t.Helper()
	watchItem, err := ParseWatchItem(".example.com")
	if err != nil {
		t.Fatal(err)
	}
	parseErr := errors.New("value not needed for notification test")
	tbsHash := sha256.Sum256([]byte("fault-recovery-tbs"))
	certHash := sha256.Sum256([]byte("fault-recovery-cert"))
	return &DiscoveredCert{
		WatchItem: watchItem,
		LogEntry:  &LogEntry{Index: 99, Log: &loglist.Log{URL: "https://ct.example.invalid"}},
		Info: &certspotter.CertInfo{
			ValidityParseError:     parseErr,
			SubjectParseError:      parseErr,
			IssuerParseError:       parseErr,
			SerialNumberParseError: parseErr,
		},
		TBSSHA256:    tbsHash,
		SHA256:       certHash,
		PubkeySHA256: certHash,
		Identifiers:  &certspotter.Identifiers{DNSNames: []string{"www.example.com"}},
	}
}

func TestFaultRecoveryReplaysPendingCertificateNotification(t *testing.T) {
	ctx := context.Background()
	stateDir := t.TempDir()
	countPath := filepath.Join(stateDir, "deliveries.log")
	scriptPath := filepath.Join(stateDir, "notify.sh")
	script := "#!/bin/sh\n" +
		"test -f \"$CERT_FILENAME\" || exit 3\n" +
		"printf '%s\\n' \"$TBS_SHA256\" >> '" + countPath + "'\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0777); err != nil {
		t.Fatal(err)
	}

	failing := &FilesystemState{
		StateDir: stateDir,
		CacheDir: filepath.Join(stateDir, "cache"),
		Script:   filepath.Join(stateDir, "does-not-exist"),
	}
	if err := failing.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	cert := faultRecoveryCert(t)
	if err := failing.NotifyCert(ctx, cert); err == nil {
		t.Fatal("expected initial notification to fail")
	}
	recordPath := failing.pendingNotificationPath(hex.EncodeToString(cert.TBSSHA256[:]))
	if !fileExists(recordPath) {
		t.Fatal("expected durable pending notification record before delivery")
	}

	restarted := &FilesystemState{
		StateDir: stateDir,
		CacheDir: filepath.Join(stateDir, "cache"),
		Script:   scriptPath,
	}
	if err := restarted.Prepare(ctx); err != nil {
		t.Fatalf("startup recovery failed: %v", err)
	}

	delivered, err := os.ReadFile(countPath)
	if err != nil {
		t.Fatalf("recovered notification was not delivered: %v", err)
	}
	if got := strings.TrimSpace(string(delivered)); got != hex.EncodeToString(cert.TBSSHA256[:]) {
		t.Fatalf("delivered hash = %q, want %x", got, cert.TBSSHA256)
	}
	if fileExists(recordPath) {
		t.Fatal("pending notification record was not completed")
	}
}

type faultRecoveryOversizeLog struct {
	maxEntriesPerRequest uint64
}

func (*faultRecoveryOversizeLog) GetSTH(context.Context) (*cttypes.SignedTreeHead, string, error) {
	panic("unexpected GetSTH")
}

func (*faultRecoveryOversizeLog) GetRoots(context.Context) ([][]byte, error) {
	panic("unexpected GetRoots")
}

func (*faultRecoveryOversizeLog) ReconstructTree(context.Context, *cttypes.SignedTreeHead) (*merkletree.CollapsedTree, error) {
	panic("unexpected ReconstructTree")
}

func (l *faultRecoveryOversizeLog) GetEntries(_ context.Context, start, endInclusive uint64) ([]ctclient.Entry, error) {
	count := endInclusive - start + 1
	if count > l.maxEntriesPerRequest {
		return nil, ctclient.ErrResponseTooLarge
	}
	entries := make([]ctclient.Entry, count)
	for i := range count {
		entries[i] = &ctclient.RFC6962LogEntry{Leaf_input: []byte{byte(start + i)}}
	}
	return entries, nil
}

func TestFaultRecoverySplitsOversizedEntryRange(t *testing.T) {
	client := &faultRecoveryOversizeLog{maxEntriesPerRequest: 2}
	entries, err := getEntriesFull(context.Background(), client, 0, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 8 {
		t.Fatalf("got %d entries, want 8 recovered entries", len(entries))
	}
}
