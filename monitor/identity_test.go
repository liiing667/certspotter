package monitor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/certspotter"
	"software.sslmate.com/src/certspotter/ctclient"
	"software.sslmate.com/src/certspotter/cttypes"
	"software.sslmate.com/src/certspotter/loglist"
)

type uid43576IdentityEntry struct {
	ctclient.Entry
	leafInput      []byte
	precertificate cttypes.ASN1Cert
	chain          cttypes.ASN1CertChain
	chainErr       error
}

func (e *uid43576IdentityEntry) LeafInput() []byte { return e.leafInput }

func (e *uid43576IdentityEntry) Precertificate() (cttypes.ASN1Cert, error) {
	return e.precertificate, nil
}

func (e *uid43576IdentityEntry) GetChain(context.Context, ctclient.IssuerGetter) (cttypes.ASN1CertChain, error) {
	return e.chain, e.chainErr
}

type uid43576IdentityState struct {
	StateProvider
	certNotifications      int
	malformedNotifications []error
	conflicts              []*IdentityConflict
	loadedConflict         *IdentityConflict
}

func (s *uid43576IdentityState) NotifyCert(context.Context, *DiscoveredCert) error {
	s.certNotifications++
	return nil
}

func (s *uid43576IdentityState) NotifyMalformedEntry(_ context.Context, _ *LogEntry, err error) error {
	s.malformedNotifications = append(s.malformedNotifications, err)
	return nil
}

func (s *uid43576IdentityState) RecordIdentityConflict(_ context.Context, conflict *IdentityConflict) error {
	s.conflicts = append(s.conflicts, conflict)
	return nil
}

func (s *uid43576IdentityState) LoadIdentityConflict(context.Context, IdentityRef) (*IdentityConflict, error) {
	return s.loadedConflict, nil
}

func uid43576TestTBSCertificate(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(43576),
		Subject:               pkix.Name{CommonName: "identity.example.test"},
		DNSNames:              []string{"identity.example.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.RawTBSCertificate
}

func uid43576ValidPrecertPair(t *testing.T) (cttypes.ASN1Cert, cttypes.TBSCertificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	poisonOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(43577),
		Subject:      pkix.Name{CommonName: "valid-identity.example.test"},
		DNSNames:     []string{"valid-identity.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{
			Id:       poisonOID,
			Critical: true,
			Value:    []byte{0x05, 0x00},
		}},
	}
	precertDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	precert, err := certspotter.ParseCertificate(precertDER)
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := precert.ParseTBSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	extensions := make([]certspotter.Extension, 0, len(tbs.Extensions))
	for _, extension := range tbs.Extensions {
		if extension.Id.Equal(poisonOID) {
			continue
		}
		extensions = append(extensions, extension)
	}
	tbs.Extensions = extensions
	tbs.Raw = nil
	leafTBS, err := asn1.Marshal(*tbs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certspotter.ValidatePrecert(precertDER, leafTBS); err != nil {
		t.Fatalf("test fixture is not a valid precert identity pair: %v", err)
	}
	return cttypes.ASN1Cert(precertDER), cttypes.TBSCertificate(leafTBS)
}

func TestUID43576ProcessPrecertRejectsIdentityMismatch(t *testing.T) {
	tbs := uid43576TestTBSCertificate(t)
	badPrecert := cttypes.ASN1Cert("this is not a DER precertificate")
	state := &uid43576IdentityState{}
	watchItem, err := ParseWatchItem(".")
	if err != nil {
		t.Fatal(err)
	}
	config := &Config{State: state, WatchList: WatchList{watchItem}}
	precert := &cttypes.PreCert{TBSCertificate: cttypes.TBSCertificate(tbs)}
	leaf := &cttypes.MerkleTreeLeaf{
		Version:  cttypes.V1,
		LeafType: cttypes.TimestampedEntryType,
		TimestampedEntry: &cttypes.TimestampedEntry{
			Timestamp:          uint64(time.Now().UnixNano()),
			EntryType:          cttypes.PrecertEntryType,
			SignedEntryPreCert: precert,
		},
	}
	leafInput, err := leaf.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	entry := &LogEntry{
		Entry: &uid43576IdentityEntry{
			leafInput:      leafInput,
			precertificate: badPrecert,
		},
		Index: 7,
		Log:   &loglist.Log{LogID: cttypes.LogID{9}},
	}

	if err := ProcessLogEntry(context.Background(), config, nil, entry); err != nil {
		t.Fatalf("ProcessLogEntry returned error: %v", err)
	}

	if state.certNotifications != 0 {
		t.Fatalf("NotifyCert called %d times; mismatched identity must not enter trusted stream", state.certNotifications)
	}
	if len(state.malformedNotifications) != 1 {
		t.Fatalf("got %d malformed notifications, want 1", len(state.malformedNotifications))
	}
	if !IsIdentityMismatch(state.malformedNotifications[0]) {
		t.Fatalf("malformed error %v does not wrap ErrIdentityMismatch", state.malformedNotifications[0])
	}
	if len(state.conflicts) != 1 {
		t.Fatalf("got %d identity conflict records, want 1", len(state.conflicts))
	}
	wantTBS := sha256.Sum256(tbs)
	wantPrecert := sha256.Sum256(badPrecert)
	if got := state.conflicts[0].Ref.TBSSHA256; got != wantTBS {
		t.Fatalf("TBS hash %x, want %x", got, wantTBS)
	}
	if got := state.conflicts[0].Ref.CertificateSHA256; got != wantPrecert {
		t.Fatalf("precert hash %x, want %x", got, wantPrecert)
	}
}

func TestUID43576ProcessPrecertAcceptsMatchingIdentity(t *testing.T) {
	precertBytes, tbs := uid43576ValidPrecertPair(t)
	state := &uid43576IdentityState{}
	watchItem, err := ParseWatchItem(".")
	if err != nil {
		t.Fatal(err)
	}
	config := &Config{State: state, WatchList: WatchList{watchItem}}
	entry := &LogEntry{
		Entry: &uid43576IdentityEntry{precertificate: precertBytes},
		Index: 8,
		Log:   &loglist.Log{LogID: cttypes.LogID{10}},
	}

	if err := processPrecertLogEntry(context.Background(), config, nil, entry, &cttypes.PreCert{TBSCertificate: tbs}); err != nil {
		t.Fatalf("processPrecertLogEntry returned error: %v", err)
	}
	if state.certNotifications != 1 {
		t.Fatalf("got %d NotifyCert calls, want matching precert to enter stream once", state.certNotifications)
	}
	if len(state.malformedNotifications) != 0 {
		t.Fatalf("unexpected malformed notifications: %v", state.malformedNotifications)
	}
	if len(state.conflicts) != 0 {
		t.Fatalf("unexpected identity conflicts: %+v", state.conflicts)
	}
}

func TestUID43576FilesystemNotifyCertRefusesMismatch(t *testing.T) {
	stateDir := t.TempDir()
	state := &FilesystemState{StateDir: stateDir}
	tbsHash := sha256.Sum256([]byte("claimed TBS identity"))
	certHash := sha256.Sum256([]byte("different concrete certificate"))
	cert := &DiscoveredCert{
		TBSSHA256:     tbsHash,
		SHA256:        certHash,
		IdentityError: ErrIdentityMismatch,
	}
	notifiedPath := filepath.Join(stateDir, "certs",
		hex.EncodeToString(tbsHash[:1]),
		"."+hex.EncodeToString(tbsHash[:])+".notified")
	if err := os.MkdirAll(filepath.Dir(notifiedPath), 0777); err != nil {
		t.Fatal(err)
	}
	originalMarker := []byte("authorization-marker-must-not-override-identity-rejection")
	if err := os.WriteFile(notifiedPath, originalMarker, 0666); err != nil {
		t.Fatal(err)
	}

	err := state.NotifyCert(context.Background(), cert)
	if !errors.Is(err, ErrUntrustedIdentity) {
		t.Fatalf("NotifyCert error %v, want ErrUntrustedIdentity", err)
	}
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("NotifyCert error %v, want ErrIdentityMismatch in chain", err)
	}

	marker, err := os.ReadFile(notifiedPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(marker) != string(originalMarker) {
		t.Fatalf("authorization/dedup marker was overwritten: %q", marker)
	}
}

func TestUID43576IdentityConflictWriteOnce(t *testing.T) {
	state := &FilesystemState{StateDir: t.TempDir()}
	ref := IdentityRef{
		TBSSHA256:         sha256.Sum256([]byte("tbs")),
		CertificateSHA256: sha256.Sum256([]byte("first cert")),
	}
	first := &IdentityConflict{Ref: ref, Reason: errors.New("first rejection"), EntryIndex: 11}
	if err := state.RecordIdentityConflict(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := &IdentityConflict{Ref: ref, Reason: errors.New("second conclusion"), EntryIndex: 22}
	if err := state.RecordIdentityConflict(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	loaded, err := state.LoadIdentityConflict(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.EntryIndex != 11 {
		t.Fatalf("entry index %d, want original 11 (rejection must not be overwritten)", loaded.EntryIndex)
	}
	if loaded.Reason == nil || !strings.Contains(loaded.Reason.Error(), "first rejection") {
		t.Fatalf("reason %v does not preserve first rejection", loaded.Reason)
	}
}

func TestUID43576TransientChainErrorDoesNotInvalidateIdentity(t *testing.T) {
	cert := &DiscoveredCert{
		TBSSHA256:        sha256.Sum256([]byte("tbs")),
		SHA256:           sha256.Sum256([]byte("leaf")),
		IdentityVerified: true,
		ChainError:       errors.New("error retrieving issuer: network unavailable"),
	}
	if err := cert.ValidateIdentity(); err != nil {
		t.Fatalf("transient chain error classified as identity failure: %v", err)
	}
	if !cert.IdentityConsistent() || !cert.TrustedIdentity() {
		t.Fatal("certificate with only a transient chain error should retain its identity trust")
	}
}

func TestUID43576PersistedRejectionBlocksAfterStateReopen(t *testing.T) {
	stateDir := t.TempDir()
	ref := IdentityRef{
		TBSSHA256:         sha256.Sum256([]byte("restart tbs")),
		CertificateSHA256: sha256.Sum256([]byte("restart cert")),
	}
	first := &FilesystemState{StateDir: stateDir}
	if err := first.RecordIdentityConflict(context.Background(), &IdentityConflict{
		Ref:        ref,
		Reason:     ErrIdentityMismatch,
		EntryIndex: 31,
	}); err != nil {
		t.Fatal(err)
	}

	// A new state instance models certspotter reopening its state directory
	// after a crash or restart.  A structurally clean cert carrying the same
	// identity pair must still observe the durable rejection.
	reopened := &FilesystemState{StateDir: stateDir}
	cert := &DiscoveredCert{
		TBSSHA256:        ref.TBSSHA256,
		SHA256:           ref.CertificateSHA256,
		IdentityVerified: true,
	}
	err := reopened.NotifyCert(context.Background(), cert)
	if !errors.Is(err, ErrUntrustedIdentity) {
		t.Fatalf("NotifyCert after reopen error %v, want ErrUntrustedIdentity", err)
	}
}

func TestUID43576LegacyMismatchTextIsRejected(t *testing.T) {
	cert := &DiscoveredCert{
		TBSSHA256:  sha256.Sum256([]byte("tbs")),
		SHA256:     sha256.Sum256([]byte("leaf")),
		ChainError: errors.New("precertificate in extra_data does not match TBSCertificate in leaf_input: serial number not equal"),
	}
	if err := cert.ValidateIdentity(); !IsIdentityMismatch(err) {
		t.Fatalf("legacy mismatch error %v was not classified", err)
	}
	state := &FilesystemState{StateDir: t.TempDir()}
	if err := state.checkCertIdentityAllowed(context.Background(), cert); !errors.Is(err, ErrUntrustedIdentity) {
		t.Fatalf("checkCertIdentityAllowed error %v, want ErrUntrustedIdentity", err)
	}
}
